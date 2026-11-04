import gc
import json
import asyncio

import pytest

from asysocks.unicomm.common import socktrack
from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.common.proxy import UniProxyTarget, UniProxyProto
from asysocks.unicomm.common.packetizers import Packetizer
from asysocks.unicomm.client import UniClient


@pytest.fixture
def tracker():
	t = socktrack.enable(start_reporter=False, eof_grace=0, linger=3600)
	yield t
	socktrack.disable()


async def _server(handler):
	server = await asyncio.start_server(handler, '127.0.0.1', 0)
	return server, server.sockets[0].getsockname()[1]


async def _silent(reader, writer):
	await reader.read()
	writer.close()


async def _hangup(reader, writer):
	writer.close()


def _client(port, protocol=UniProto.CLIENT_TCP, timeout=5, proxies=None):
	return UniClient(UniTarget('127.0.0.1', port, protocol, timeout=timeout, proxies=proxies), Packetizer())


def test_disabled_tracks_nothing():
	assert socktrack.TRACKER is None

	async def run():
		server, port = await _server(_silent)
		async with server:
			conn = await _client(port).connect()
			assert conn.sockrec is None
			await conn.close()

	asyncio.run(run())


def test_close_untracks(tracker):
	async def run():
		server, port = await _server(_silent)
		async with server:
			conn = await _client(port).connect()
			snap = tracker.snapshot()
			assert snap['live'] == 1
			assert snap['top_origins'][0]['origin'].startswith(__file__)
			await conn.close()
			snap = tracker.snapshot()
			assert snap['live'] == 0
			assert snap['totals']['closed'] == 1

	asyncio.run(run())


def test_orphan_detected(tracker):
	async def run():
		server, port = await _server(_silent)
		async with server:
			conn = await _client(port).connect()
			writer = conn.writer
			del conn
			gc.collect()
			snap = tracker.snapshot()
			assert snap['categories']['orphan'] == 1
			assert snap['totals']['orphaned'] == 1
			# reported only once
			tracker.snapshot()
			assert tracker.orphaned == 1
			writer.close()
			assert tracker.snapshot()['live'] == 0

	asyncio.run(run())


def test_gc_released_socket_reported(tracker):
	async def run():
		server, port = await _server(_silent)
		async with server:
			conn = await _client(port).connect()
			transport = conn.writer.transport
			del conn
			gc.collect()
			if transport.is_closing() is False:
				pytest.skip('StreamWriter does not close on GC on this Python version')
			snap = tracker.snapshot()
			assert snap['live'] == 0
			assert snap['totals']['gc_closed'] == 1
			assert snap['gc_closed_by_origin'][0]['origin'].startswith(__file__)

	asyncio.run(run())


def test_eof_unclosed_detected(tracker):
	async def run():
		server, port = await _server(_hangup)
		async with server:
			conn = await _client(port).connect()
			async for _ in conn.read():
				pass
			snap = tracker.snapshot()
			assert snap['categories']['eof_unclosed'] == 1
			await conn.close()
			assert tracker.snapshot()['live'] == 0

	asyncio.run(run())


def test_failed_tls_handshake_closes_socket(tracker):
	async def run():
		server, port = await _server(_hangup)
		async with server:
			with pytest.raises(BaseException):
				await _client(port, protocol=UniProto.CLIENT_SSL_TCP, timeout=2).connect()
			snap = tracker.snapshot()
			assert snap['live'] == 0
			assert snap['totals']['failed'] == 1

	asyncio.run(run())


def test_cancelled_proxy_link_closes_socket(tracker):
	async def run():
		server, port = await _server(_silent)
		async with server:
			proxy = UniProxyTarget()
			proxy.server_ip = '127.0.0.1'
			proxy.server_port = port
			proxy.protocol = UniProxyProto.CLIENT_SOCKS5_TCP
			proxy.timeout = 30
			client = _client(1, timeout=0.3, proxies=[proxy])
			with pytest.raises(asyncio.TimeoutError):
				await client.connect()
			snap = tracker.snapshot()
			assert snap['live'] == 0
			assert snap['totals']['failed'] == 1
			assert snap['opened_by_kind'] == {socktrack.KIND_PROXY: 1}

	asyncio.run(run())


def test_report_and_dump(tracker, tmp_path):
	async def run():
		server, port = await _server(_silent)
		async with server:
			conn = await _client(port).connect()
			tracker.report()
			path = tmp_path / 'report.json'
			data = json.loads(socktrack.dump_report(str(path)))
			assert data['live'] == 1
			assert data['records'][0]['kind'] == socktrack.KIND_TCP
			assert json.loads(path.read_text())['live'] == 1
			await conn.close()

	asyncio.run(run())
