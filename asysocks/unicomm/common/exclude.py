import re
import ipaddress

# Process-global target exclude list.
#
# Upper layers (the ~100 modules building on this library) can register
# targets that must never be connected to. Entries may be:
#   - a single IP address      e.g. '169.254.169.254'
#   - a CIDR range             e.g. '10.0.0.0/8'
#   - a hostname regex pattern e.g. r'.*\.internal\.corp$'
#
# Normalized entries are stored as (original_str, matcher) tuples where matcher
# is either an ipaddress network object or a compiled regex Pattern.
EXCLUDE_LIST = []


class TargetExcludedException(Exception):
	def __init__(self, target):
		self.target = target
		super().__init__('Target "%s" is on the exclude list!' % target)


def add_exclude(entry:str):
	"""
	Register an exclude entry. The entry is classified once on insert: if it
	parses as an IP/CIDR it is stored as a network, otherwise it is compiled as
	a case-insensitive regex matched against hostnames (and IP strings).
	Duplicate entries (by original string) are ignored.
	"""
	entry = str(entry)
	for original, _ in EXCLUDE_LIST:
		if original == entry:
			return

	try:
		matcher = ipaddress.ip_network(entry, strict=False)
	except Exception:
		matcher = re.compile(entry, re.IGNORECASE)

	EXCLUDE_LIST.append((entry, matcher))


def remove_exclude(entry:str):
	entry = str(entry)
	for i, (original, _) in enumerate(EXCLUDE_LIST):
		if original == entry:
			del EXCLUDE_LIST[i]
			return


def clear_excludes():
	EXCLUDE_LIST.clear()


def get_excludes():
	return [original for original, _ in EXCLUDE_LIST]


def is_excluded(value:str) -> bool:
	"""
	Returns True if the given IP or hostname matches any exclude entry.
	Tolerant by design: a malformed stored entry never raises during a check.
	"""
	if value is None:
		return False
	value = str(value)

	ipaddr = None
	try:
		ipaddr = ipaddress.ip_address(value)
	except Exception:
		ipaddr = None

	for _, matcher in EXCLUDE_LIST:
		try:
			if isinstance(matcher, re.Pattern):
				if matcher.search(value) is not None:
					return True
			elif ipaddr is not None:
				if ipaddr in matcher:
					return True
		except Exception:
			continue
	return False


def check_target_excluded(*values):
	"""
	Raises TargetExcludedException if any of the provided (non-None) values is
	on the exclude list.
	"""
	for value in values:
		if value is None:
			continue
		if is_excluded(value):
			raise TargetExcludedException(value)
