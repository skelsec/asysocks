import ssl
import copy
import asyncio
import traceback
import ipaddress
from asysocks.unicomm.common.target import UniTarget
from asysocks.unicomm.common.packetizers import Packetizer, StreamPacketizer
from asysocks.unicomm.common.packetizers.ssl import PacketizerSSL
from asysocks.unicomm.common.transport import UNITransport


class UniConnection:
	def __init__(self, reader:asyncio.StreamReader, writer:asyncio.StreamWriter, packetizer:Packetizer, peer_ip:str = None, peer_port:int = None):
		self.reader = reader
		self.writer = writer
		self.packetizer = packetizer
		self.peer_ip = peer_ip #for connection types where reader/writer does not have get_extra_info
		self.peer_port = peer_port
		self.packetizer_task = None
		self.closing = False
		self.closed_evt = asyncio.Event()

		self.read_lock:asyncio.Lock = asyncio.Lock()
		self.read_resume:asyncio.Event = asyncio.Event()
		self.read_resume.set()

	async def __aenter__(self):
		return self

	async def __aexit__(self, exc_type, exc, tb):
		await self.close()
		
	def get_extra_info(self, name, default=None):
		if name == 'peername' and self.peer_ip is not None:
			return (self.peer_ip, self.peer_port)
		
		if hasattr(self.reader, 'get_extra_info'):
			return self.reader.get_extra_info(name, default)
		
		return default

	def get_peer_certificate(self):
		return self.packetizer.get_peer_certificate()
	
	def change_packetizer(self, packetizer):
		rem_data = self.packetizer.flush_buffer()
		if isinstance(self.packetizer, PacketizerSSL):
			self.packetizer.packetizer = packetizer
		else:
			self.packetizer = packetizer
	
	def packetizer_control(self, *args, **kw):
		return self.packetizer.packetizer_control(*args, **kw)

	async def wrap_ssl(self, ssl_ctx = None, packetizer = None):
		if packetizer is None:
			packetizer = self.packetizer
		if ssl_ctx is None:
			ssl_ctx = ssl.create_default_context()
			ssl_ctx.check_hostname = False
			ssl_ctx.verify_mode = ssl.CERT_NONE
		self.packetizer = PacketizerSSL(ssl_ctx, packetizer)
		await self.packetizer.do_handshake(self.reader, self.writer)

	async def close(self):
		self.closing = True
		if self.writer is not None:
			self.writer.close()
		self.closed_evt.set()

	async def drain(self):
		return

	async def write(self, data):
		async for packet in self.packetizer.data_out(data):
			self.writer.write(packet)
			await self.writer.drain()

	async def read_one(self):
		async for packet in self.read():
			return packet

	async def read(self):
		try:
			data = None
			while self.closing is False:
				async for result in self.packetizer.data_in(data):
					if result is None:
						break
					yield result
				
				data = await self.reader.read(self.packetizer.buffer_size)
				if data == b'':
					break
			
			#flush the buffer, test if there is any data left
			data = None
			async for result in self.packetizer.data_in(data):
				if result is None:
					break
				yield result
		except Exception as e:
			yield None
	
	async def stream(self):
		if not isinstance(self.packetizer, StreamPacketizer):
			raise Exception('This function onaly available when StreamPacketizer is used!')
		while True:
			data = await self.reader.read(self.packetizer.buffer_size)
			await self.packetizer.data_in(data)
			if data == b'':
				break
	

	### PROTOCOL INTERFACE
	async def pause_reading(self):
		self.read_resume.clear()
		async with self.read_lock:
			await self.read_resume.wait()
	
	async def __transport_reader(self, protocol:asyncio.Protocol):
		err = None
		try:
			data = None
			while True:
				async with self.read_lock:
					async for result in self.packetizer.data_in(data):
						if result is None:
							protocol.eof_received()
							break
						protocol.data_received(result)
					
					data = await self.reader.read(self.packetizer.buffer_size)
					if data == b'':
						protocol.eof_received()
						break
		except Exception as e:
			traceback.print_exc()
			err = e
		finally:
			protocol.connection_lost(err)
	
	async def get_transport(self, protocol:asyncio.Protocol):
		transport = UNITransport(self, protocol)
		protocol.connection_made(transport)
		x = asyncio.create_task(self.__transport_reader(protocol))
		return transport


class UniUDPConnection:
	def __init__(self, socket, data, addr):
		self.socket = socket
		self.data = data
		self.addr = addr





"""Provide high-level UDP endpoints for asyncio.
Example:
async def main():
	# Create a local UDP enpoint
	local = await open_local_endpoint('localhost', 8888)
	# Create a remote UDP enpoint, pointing to the first one
	remote = await open_remote_endpoint(*local.address)
	# The remote endpoint sends a datagram
	remote.send(b'Hey Hey, My My')
	# The local endpoint receives the datagram, along with the address
	data, address = await local.receive()
	# This prints: Got 'Hey Hey, My My' from 127.0.0.1 port 8888
	print(f"Got {data!r} from {address[0]} port {address[1]}")

TAKEN FROM: https://gist.github.com/vxgmichel/e47bff34b68adb3cf6bd4845c4bed448
License: MIT
"""


# Imports

import asyncio
import warnings


# Datagram protocol

class DatagramEndpointProtocol(asyncio.DatagramProtocol):
	"""Datagram protocol for the endpoint high-level interface."""

	def __init__(self, endpoint):
		self._endpoint = endpoint

	# Protocol methods

	def connection_made(self, transport):
		self._endpoint._transport = transport

	def connection_lost(self, exc):
		assert exc is None
		if self._endpoint._write_ready_future is not None:
			self._endpoint._write_ready_future.set_result(None)
		self._endpoint.close()

	# Datagram protocol methods

	def datagram_received(self, data, addr):
		self._endpoint.feed_datagram(data, addr)

	def error_received(self, exc):
		msg = 'Endpoint received an error: {!r}'
		warnings.warn(msg.format(exc))

	# Workflow control

	def pause_writing(self):
		assert self._endpoint._write_ready_future is None
		loop = self._endpoint._transport._loop
		self._endpoint._write_ready_future = loop.create_future()

	def resume_writing(self):
		assert self._endpoint._write_ready_future is not None
		self._endpoint._write_ready_future.set_result(None)
		self._endpoint._write_ready_future = None


# Enpoint classes

class Endpoint:
	"""High-level interface for UDP enpoints.
	Can either be local or remote.
	It is initialized with an optional queue size for the incoming datagrams.
	"""

	def __init__(self, target:UniTarget, queue_size=None):
		self.target = target
		if queue_size is None:
			queue_size = 0
		self._queue = asyncio.Queue(queue_size)
		self._closed = False
		self._transport = None
		self._write_ready_future = None

	# Protocol callbacks

	def feed_datagram(self, data, addr):
		try:
			self._queue.put_nowait((data, addr))
		except asyncio.QueueFull:
			warnings.warn('Endpoint queue is full')

	def close(self):
		# Manage flag
		if self._closed:
			return
		self._closed = True
		# Wake up
		if self._queue.empty():
			self.feed_datagram(None, None)
		# Close transport
		if self._transport:
			self._transport.close()

	# User methods

	async def write(self, data, addr = None):
		"""Send a datagram to the given address."""
		if addr is None:
			addr = (self.target.get_ip_or_hostname(), self.target.port)
		return self.send(data, addr)
	
	async def read(self, with_addr = False):
		"""Wait for an incoming datagram and return it with
		the corresponding address.
		This method is a coroutine.
		"""
		while not self._closed:
			data, addr = await self.receive()
			if data is None:
				self.close()
				break

			result = (data, addr)
			if with_addr is True:
				yield result
			else:
				yield data
			
	async def read_one(self, with_addr = False):
		"""Wait for an incoming datagram and return it with
		the corresponding address.
		This method is a coroutine.
		"""
		data, addr = await self.receive()
		if data is None:
			self.close()
			return None
		if with_addr is True:
			return (data, addr)
		return data
	
	def send(self, data, addr):
		"""Send a datagram to the given address."""
		if self._closed:
			raise IOError("Enpoint is closed")
		if asyncio.iscoroutine(self._transport.sendto) is True:
			# absolutetly not a good idea to do this, but it works
			x = asyncio.create_task(self._transport.sendto(data, addr))
		else:
			self._transport.sendto(data, addr)

	async def receive(self):
		"""Wait for an incoming datagram and return it with
		the corresponding address.
		This method is a coroutine.
		"""
		if self._queue.empty() and self._closed:
			raise IOError("Enpoint is closed")
		data, addr = await self._queue.get()
		if data is None:
			raise IOError("Enpoint is closed")
		return data, addr

	def abort(self):
		"""Close the transport immediately."""
		if self._closed:
			raise IOError("Enpoint is closed")
		self._transport.abort()
		self.close()

	async def drain(self):
		"""Drain the transport buffer below the low-water mark."""
		if self._write_ready_future is not None:
			await self._write_ready_future

	# Properties

	@property
	def address(self):
		"""The endpoint address as a (host, port) tuple."""
		return self._transport.get_extra_info("socket").getsockname()

	@property
	def closed(self):
		"""Indicates whether the endpoint is closed or not."""
		return self._closed


class LocalEndpoint(Endpoint):
	"""High-level interface for UDP local enpoints.
	It is initialized with an optional queue size for the incoming datagrams.
	"""
	pass


class RemoteEndpoint(Endpoint):
	"""High-level interface for UDP remote enpoints.
	It is initialized with an optional queue size for the incoming datagrams.
	"""

	def send(self, data):
		"""Send a datagram to the remote host."""
		super().send(data, None)

	async def receive(self):
		""" Wait for an incoming datagram from the remote host.
		This method is a coroutine.
		"""
		data, addr = await super().receive()
		return data
