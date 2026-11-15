"""
Optional socket lifecycle tracker for unicomm.

Disabled by default. When disabled, TRACKER is None and every hook is a
single function call that returns immediately; nothing runs on the
read/write path.

Enable it either with environment variables (no code change needed in the
modules that use this library):

	ASYSOCKS_SOCKTRACK=1                 enable tracking
	ASYSOCKS_SOCKTRACK_INTERVAL=30       seconds between periodic reports
	ASYSOCKS_SOCKTRACK_LINGER=300        age (s) after which an open socket is "lingering"
	ASYSOCKS_SOCKTRACK_PENDING=120       age (s) after which a socket that never got an owner is "stuck_pending"
	ASYSOCKS_SOCKTRACK_EOF_GRACE=10      seconds after peer EOF before an unclosed socket is "eof_unclosed"
	ASYSOCKS_SOCKTRACK_STACK=1           capture the caller stack for every socket (slower)
	ASYSOCKS_SOCKTRACK_WARN_LIVE=5000    emit a detailed report when this many sockets are live
	ASYSOCKS_SOCKTRACK_WARN_FD_RATIO=0.8 emit a detailed report when process FDs reach this share of the limit
	ASYSOCKS_SOCKTRACK_DUMP=/path.json   write a JSON report on every threshold breach
	ASYSOCKS_SOCKTRACK_TOP=10            number of origins/targets shown in reports

or from code:

	from asysocks.unicomm.common import socktrack
	socktrack.enable(interval=10, warn_live=2000)
	...
	print(socktrack.dump_report())

Sockets are recorded when they are created, before any proxy negotiation or
TLS handshake, so sockets lost during connection setup are tracked as well.
A background daemon thread classifies the records instead of relying on every
close path being instrumented; the thread keeps reporting while the event
loop is overloaded.

Categories:
	orphan         the owning connection object was garbage collected but the
	               socket is still open; nothing can close it anymore
	eof_unclosed   the peer closed the connection but close() was never called
	               on our side (CLOSE_WAIT)
	stuck_pending  the socket was created but no connection object ever took
	               ownership of it within the pending timeout
	lingering      open for longer than the linger threshold
	gc_closed      (cumulative) the socket was never closed explicitly and only
	               got closed because its owner was garbage collected (Python
	               3.11+ StreamWriter.__del__). Same bug as orphan, but the
	               socket lived until the GC got to it.
"""

import os
import sys
import json
import time
import asyncio
import logging
import threading
import traceback
import itertools
import weakref
import collections

logger = logging.getLogger('asysocks.socktrack')

TRACKER = None

KIND_TCP = 'tcp'          # direct TCP connection to the target
KIND_PROXY = 'proxy'      # TCP connection to the first proxy in the chain
KIND_VIRTUAL = 'virtual'  # proxied over a websocket (WSNET etc.), no dedicated local socket
KIND_UDP = 'udp'
KIND_INBOUND = 'inbound'  # accepted by a UniServer

_ASYSOCKS_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SKIP_DIRS = tuple(
	os.path.normcase(p) + os.sep for p in (
		os.path.join(_ASYSOCKS_DIR, 'unicomm'),
		os.path.join(_ASYSOCKS_DIR, 'network'),
		os.path.dirname(os.path.abspath(asyncio.__file__)),
	)
)
_external_cache = {}


class SockRecord:
	__slots__ = (
		'tracker', 'id', 'kind', 'target', 'origin', 'stack',
		'created_at', 'owned_at', 'eof_at', 'closed_at',
		'handle_ref', 'owner_ref', 'orphan_reported',
	)

	def to_dict(self, now):
		return {
			'id': self.id,
			'kind': self.kind,
			'target': self.target,
			'origin': self.origin,
			'age': round(now - self.created_at, 3),
			'owned': self.owner_ref is not None,
			'eof_age': None if self.eof_at is None else round(now - self.eof_at, 3),
			'stack': self.stack,
		}


def _weak(obj):
	if obj is None:
		return None
	try:
		return weakref.ref(obj)
	except TypeError:
		return None


def _is_external(filename):
	result = _external_cache.get(filename)
	if result is None:
		if not filename or filename[0] == '<':
			result = False
		else:
			result = not os.path.normcase(os.path.abspath(filename)).startswith(_SKIP_DIRS)
		_external_cache[filename] = result
	return result


def _find_origin(capture_stack):
	"""
	Returns the first stack frame outside unicomm/network/asyncio as 'file:func:line',
	plus the list of external frames when capture_stack is set.
	"""
	frame = sys._getframe(1)
	origin = None
	stack = [] if capture_stack else None
	while frame is not None:
		code = frame.f_code
		if _is_external(code.co_filename):
			entry = '%s:%s:%s' % (code.co_filename, code.co_name, frame.f_lineno)
			if origin is None:
				origin = entry
				if stack is None:
					break
			if len(stack) < 25:
				stack.append(entry)
		frame = frame.f_back
	return origin or '<unknown>', stack


def _describe_target(target):
	if target is None:
		return '<unknown>'
	if isinstance(target, str):
		return target
	if isinstance(target, tuple) and len(target) >= 2:
		return '%s:%s' % (target[0], target[1])
	try:
		return '%s:%s' % (target.get_ip_or_hostname(), target.port)
	except Exception:
		return repr(target)


def _get_handle(obj):
	"""
	Returns the object that represents the OS level socket: the asyncio
	transport for StreamWriters, the transport itself for datagram endpoints.
	"""
	transport = getattr(obj, 'transport', None)
	if transport is not None:
		return transport
	if hasattr(obj, 'get_extra_info') and hasattr(obj, 'is_closing'):
		return obj
	return None


def _handle_closing(handle):
	try:
		return handle.is_closing()
	except Exception:
		return False


def get_process_fd_count():
	"""Number of FDs (POSIX) or handles (Windows, requires psutil) held by this process, or None."""
	try:
		if sys.platform.startswith('linux'):
			return len(os.listdir('/proc/self/fd'))
		if sys.platform == 'darwin' or 'bsd' in sys.platform:
			return len(os.listdir('/dev/fd'))
		if sys.platform == 'win32':
			import psutil
			return psutil.Process().num_handles()
	except Exception:
		pass
	return None


def get_process_fd_limit():
	"""Soft RLIMIT_NOFILE on POSIX, None on Windows (no per-process socket limit)."""
	try:
		import resource
		soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
		if soft == resource.RLIM_INFINITY:
			return None
		return soft
	except Exception:
		return None


class SocketTracker:
	def __init__(self, interval=30, linger=300, pending_timeout=120, eof_grace=10,
				capture_stack=False, warn_live=None, warn_fd_ratio=0.8, dump_path=None, top=10):
		self.interval = interval
		self.linger = linger
		self.pending_timeout = pending_timeout
		self.eof_grace = eof_grace
		self.capture_stack = capture_stack
		self.warn_live = warn_live
		self.warn_fd_ratio = warn_fd_ratio
		self.dump_path = dump_path
		self.top = top

		self._lock = threading.Lock()
		self._ids = itertools.count(1)
		self._live = {}
		self.peak = 0
		self.peak_at = None
		self.opened = 0
		self.closed = 0
		self.failed = 0
		self.orphaned = 0
		self.gc_closed = 0
		self.gc_closed_by_origin = collections.Counter()
		self.opened_by_kind = collections.Counter()
		self._last_counts = (0, 0, 0)
		self._in_breach = False

		self._stop_evt = threading.Event()
		self._thread = None

	### hooks (called from event loop threads)

	def open(self, handle_obj, target, kind, owner=None, origin=None):
		rec = SockRecord()
		rec.tracker = self
		rec.id = next(self._ids)
		rec.kind = kind
		rec.target = _describe_target(target)
		if origin is None:
			rec.origin, rec.stack = _find_origin(self.capture_stack)
		else:
			rec.origin, rec.stack = origin, None
		rec.created_at = time.monotonic()
		rec.owned_at = None
		rec.eof_at = None
		rec.closed_at = None
		rec.handle_ref = _weak(_get_handle(handle_obj))
		rec.owner_ref = None
		rec.orphan_reported = False
		if owner is not None:
			self.attach(rec, owner)
		with self._lock:
			self._live[rec.id] = rec
			self.opened += 1
			self.opened_by_kind[kind] += 1
			if len(self._live) > self.peak:
				self.peak = len(self._live)
				self.peak_at = time.time()
		return rec

	def attach(self, rec, owner):
		rec.owner_ref = _weak(owner)
		rec.owned_at = time.monotonic()

	def close(self, rec, failed=False):
		if rec.closed_at is not None:
			return
		rec.closed_at = time.monotonic()
		with self._lock:
			if self._live.pop(rec.id, None) is not None:
				if failed:
					self.failed += 1
				else:
					self.closed += 1

	### reporting (runs in the background thread or on demand)

	def start(self):
		if self._thread is not None:
			return
		self._stop_evt.clear()
		self._thread = threading.Thread(target=self._run, name='asysocks-socktrack', daemon=True)
		self._thread.start()

	def stop(self):
		self._stop_evt.set()
		self._thread = None

	def _run(self):
		while not self._stop_evt.wait(self.interval):
			try:
				self.report()
			except Exception:
				logger.exception('[SOCKTRACK] report failed')

	def sweep(self):
		"""Drops closed records and classifies the open ones. Returns (now, records, flags)."""
		now = time.monotonic()
		with self._lock:
			records = list(self._live.values())

		alive = []
		flags = {}
		new_orphans = []
		gc_closed = []
		for rec in records:
			handle = rec.handle_ref() if rec.handle_ref is not None else None
			owner = rec.owner_ref() if rec.owner_ref is not None else None
			owner_gone = rec.owner_ref is not None and owner is None

			if rec.handle_ref is not None and (handle is None or _handle_closing(handle)):
				# closed without going through UniConnection.close
				self.close(rec)
				if owner_gone and rec.orphan_reported is False:
					gc_closed.append(rec)
				continue
			if rec.handle_ref is None:
				if owner is not None and getattr(owner, 'closing', False) is True:
					self.close(rec)
					continue
				if owner_gone:
					# virtual connection, no local socket to watch; count the owner loss and drop it
					self.close(rec)
					new_orphans.append(rec)
					continue

			f = []
			if owner_gone:
				f.append('orphan')
				if rec.orphan_reported is False:
					rec.orphan_reported = True
					new_orphans.append(rec)
			elif rec.owner_ref is None and now - rec.created_at > self.pending_timeout:
				f.append('stuck_pending')
			if rec.eof_at is not None and now - rec.eof_at > self.eof_grace:
				f.append('eof_unclosed')
			if now - rec.created_at > self.linger:
				f.append('lingering')
			alive.append(rec)
			flags[rec.id] = f

		if new_orphans or gc_closed:
			with self._lock:
				self.orphaned += len(new_orphans)
				self.gc_closed += len(gc_closed)
				for rec in gc_closed:
					self.gc_closed_by_origin[rec.origin] += 1
		for rec in gc_closed[:20]:
			logger.warning(
				'[SOCKTRACK] %s socket to %s was never closed, released by garbage collection after %.1fs; created by %s' % (
					rec.kind, rec.target, now - rec.created_at, rec.origin
				)
			)
		if len(gc_closed) > 20:
			logger.warning('[SOCKTRACK] ... and %d more sockets released by garbage collection' % (len(gc_closed) - 20))
		for rec in new_orphans[:20]:
			logger.warning(
				'[SOCKTRACK] orphaned %s socket to %s (age %.1fs) created by %s' % (
					rec.kind, rec.target, now - rec.created_at, rec.origin
				)
			)
		if len(new_orphans) > 20:
			logger.warning('[SOCKTRACK] ... and %d more orphaned sockets' % (len(new_orphans) - 20))

		return now, alive, flags

	def snapshot(self, include_records=False):
		now, alive, flags = self.sweep()
		fds = get_process_fd_count()
		fd_limit = get_process_fd_limit()

		categories = collections.Counter()
		by_origin = collections.defaultdict(collections.Counter)
		by_target = collections.Counter()
		by_kind = collections.Counter()
		for rec in alive:
			by_kind[rec.kind] += 1
			by_target[rec.target] += 1
			oc = by_origin[rec.origin]
			oc['live'] += 1
			if rec.owner_ref is None:
				oc['pending'] += 1
			for f in flags[rec.id]:
				categories[f] += 1
				oc[f] += 1

		origins = sorted(by_origin.items(), key=lambda x: x[1]['live'], reverse=True)
		pending = sum(1 for r in alive if r.owner_ref is None)
		result = {
			'time': time.time(),
			'pid': os.getpid(),
			'platform': sys.platform,
			'live': len(alive),
			'local_sockets': len(alive) - by_kind.get(KIND_VIRTUAL, 0),
			'pending': pending,
			'peak': self.peak,
			'peak_at': self.peak_at,
			'process_fds': fds,
			'process_fd_limit': fd_limit,
			'totals': {
				'opened': self.opened,
				'closed': self.closed,
				'failed': self.failed,
				'orphaned': self.orphaned,
				'gc_closed': self.gc_closed,
			},
			'gc_closed_by_origin': [{'origin': o, 'count': c} for o, c in self.gc_closed_by_origin.most_common(self.top)],
			'opened_by_kind': dict(self.opened_by_kind),
			'live_by_kind': dict(by_kind),
			'categories': {k: categories.get(k, 0) for k in ('orphan', 'eof_unclosed', 'stuck_pending', 'lingering')},
			'top_origins': [dict(origin=o, **c) for o, c in origins[:self.top]],
			'top_targets': [{'target': t, 'live': c} for t, c in by_target.most_common(self.top)],
		}
		if include_records:
			order = sorted(alive, key=lambda r: (len(flags[r.id]) == 0, r.created_at))
			result['records'] = [dict(rec.to_dict(now), flags=flags[rec.id]) for rec in order]
		return result

	def _breached(self, snap):
		if self.warn_live is not None and snap['local_sockets'] >= self.warn_live:
			return True
		fds, limit = snap['process_fds'], snap['process_fd_limit']
		if self.warn_fd_ratio and fds is not None and limit:
			return fds >= limit * self.warn_fd_ratio
		return False

	def report(self):
		snap = self.snapshot()
		opened, closed, failed = self.opened, self.closed, self.failed
		lo, lc, lf = self._last_counts
		self._last_counts = (opened, closed, failed)

		fdinfo = 'n/a'
		if snap['process_fds'] is not None:
			fdinfo = '%s/%s' % (snap['process_fds'], snap['process_fd_limit'] or '-')
		cat = snap['categories']
		lines = [
			'[SOCKTRACK] live=%d local=%d pending=%d peak=%d fds=%s | +%d opened, -%d closed, %d failed in last %ss' % (
				snap['live'], snap['local_sockets'], snap['pending'], snap['peak'], fdinfo,
				opened - lo, closed - lc, failed - lf, self.interval,
			),
			'  orphan=%d eof_unclosed=%d stuck_pending=%d lingering(>%ss)=%d orphaned_total=%d gc_closed_total=%d' % (
				cat['orphan'], cat['eof_unclosed'], cat['stuck_pending'], self.linger, cat['lingering'],
				snap['totals']['orphaned'], snap['totals']['gc_closed'],
			),
		]
		if snap['top_origins']:
			lines.append('  top origins (live / pending / orphan / eof_unclosed / lingering):')
			for o in snap['top_origins']:
				lines.append('    %6d / %d / %d / %d / %d  %s' % (
					o['live'], o.get('pending', 0), o.get('orphan', 0), o.get('eof_unclosed', 0), o.get('lingering', 0), o['origin'],
				))
		if snap['gc_closed_by_origin']:
			lines.append('  never closed, released by GC (total per origin):')
			for o in snap['gc_closed_by_origin']:
				lines.append('    %6d  %s' % (o['count'], o['origin']))

		breached = self._breached(snap)
		if breached:
			lines.append('  top targets:')
			for t in snap['top_targets']:
				lines.append('    %6d  %s' % (t['live'], t['target']))
			logger.warning('\n'.join(lines))
			if self._in_breach is False and self.dump_path:
				self.dump(self.dump_path)
		else:
			logger.info('\n'.join(lines))
		self._in_breach = breached
		return snap

	def dump(self, path=None):
		data = json.dumps(self.snapshot(include_records=True), indent=2, default=str)
		if path is not None:
			try:
				with open(path, 'w') as f:
					f.write(data)
				logger.warning('[SOCKTRACK] report written to %s' % path)
			except Exception:
				logger.exception('[SOCKTRACK] failed to write report to %s' % path)
		return data


### module level API

def enable(interval=30, linger=300, pending_timeout=120, eof_grace=10, capture_stack=False,
			warn_live=None, warn_fd_ratio=0.8, dump_path=None, top=10, start_reporter=True):
	"""
	Starts tracking sockets created from now on. Sockets that already exist are
	not tracked. Calling it again replaces the tracker and resets the counters.
	"""
	global TRACKER
	disable()
	tracker = SocketTracker(
		interval=interval, linger=linger, pending_timeout=pending_timeout, eof_grace=eof_grace,
		capture_stack=capture_stack, warn_live=warn_live, warn_fd_ratio=warn_fd_ratio,
		dump_path=dump_path, top=top,
	)
	if start_reporter:
		tracker.start()
	TRACKER = tracker
	logger.info('[SOCKTRACK] socket tracking enabled')
	return tracker


def disable():
	global TRACKER
	tracker = TRACKER
	TRACKER = None
	if tracker is not None:
		tracker.stop()


def is_enabled():
	return TRACKER is not None


def get_snapshot(include_records=False):
	tracker = TRACKER
	if tracker is None:
		return None
	return tracker.snapshot(include_records=include_records)


def dump_report(path=None):
	"""Returns (and optionally writes) a JSON report including every live socket."""
	tracker = TRACKER
	if tracker is None:
		return None
	return tracker.dump(path)


def track_open(handle_obj, target, kind, owner=None, origin=None):
	tracker = TRACKER
	if tracker is None:
		return None
	try:
		return tracker.open(handle_obj, target, kind, owner, origin)
	except Exception:
		logger.debug('[SOCKTRACK] track_open failed', exc_info=True)
		return None


def track_attach(rec, owner):
	if rec is not None:
		rec.tracker.attach(rec, owner)


def track_close(rec):
	if rec is not None:
		rec.tracker.close(rec)


def track_fail(rec):
	if rec is not None:
		rec.tracker.close(rec, failed=True)


def track_eof(rec):
	if rec is not None and rec.eof_at is None:
		rec.eof_at = time.monotonic()


def _env_number(name, conv, default):
	value = os.environ.get(name)
	if value is None or value == '':
		return default
	try:
		return conv(value)
	except ValueError:
		logger.warning('[SOCKTRACK] invalid value for %s: %r' % (name, value))
		return default


def _enable_from_env():
	if os.environ.get('ASYSOCKS_SOCKTRACK', '').strip().lower() not in ('1', 'true', 'yes', 'on'):
		return
	enable(
		interval=_env_number('ASYSOCKS_SOCKTRACK_INTERVAL', float, 30),
		linger=_env_number('ASYSOCKS_SOCKTRACK_LINGER', float, 300),
		pending_timeout=_env_number('ASYSOCKS_SOCKTRACK_PENDING', float, 120),
		eof_grace=_env_number('ASYSOCKS_SOCKTRACK_EOF_GRACE', float, 10),
		capture_stack=os.environ.get('ASYSOCKS_SOCKTRACK_STACK', '').strip().lower() in ('1', 'true', 'yes', 'on'),
		warn_live=_env_number('ASYSOCKS_SOCKTRACK_WARN_LIVE', int, None),
		warn_fd_ratio=_env_number('ASYSOCKS_SOCKTRACK_WARN_FD_RATIO', float, 0.8),
		dump_path=os.environ.get('ASYSOCKS_SOCKTRACK_DUMP') or None,
		top=_env_number('ASYSOCKS_SOCKTRACK_TOP', int, 10),
	)


_enable_from_env()
