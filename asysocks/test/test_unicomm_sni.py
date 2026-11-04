import asyncio

from asysocks.unicomm.common.connection import UniConnection
from asysocks.unicomm.common.packetizers import Packetizer
from asysocks.unicomm.common.packetizers.ssl import PacketizerSSL


class _FakeTLSObject:
	def do_handshake(self):
		return None


class _FakeSSLContext:
	def __init__(self):
		self.calls = []
		self.tls_object = _FakeTLSObject()

	def wrap_bio(self, incoming, outgoing, server_side=False, server_hostname=None):
		self.calls.append((server_side, server_hostname))
		return self.tls_object


class _FakeWriter:
	def close(self):
		return None


def test_packetizer_forwards_client_sni():
	context = _FakeSSLContext()
	packetizer = PacketizerSSL(context, Packetizer(), server_hostname='vhost.example')

	asyncio.run(packetizer.do_handshake(None, None))

	assert context.calls == [(False, 'vhost.example')]
	assert packetizer.get_ssl_object() is context.tls_object


def test_packetizer_never_forwards_sni_in_server_mode():
	context = _FakeSSLContext()
	packetizer = PacketizerSSL(context, Packetizer(), server_hostname='ignored.example')

	asyncio.run(packetizer.do_handshake(None, None, server_side=True))

	assert context.calls == [(True, None)]


def test_connection_exposes_ssl_object():
	context = _FakeSSLContext()
	packetizer = PacketizerSSL(context, Packetizer())
	packetizer.tls_obj = context.tls_object
	connection = UniConnection(None, _FakeWriter(), packetizer)

	assert connection.get_ssl_object() is context.tls_object
