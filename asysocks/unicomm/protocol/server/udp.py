import asyncio
from asyncio import DatagramProtocol, Protocol, StreamReader, StreamWriter

class UDPProtocol(Protocol):
	def __init__(self, in_queue:asyncio.Queue):
		self.in_queue = in_queue
		self.socket = None

	def connection_made(self, transport):
		self.socket = transport.get_extra_info('socket')
		self.transport = transport
	
	def datagram_received(self, data, addr):
		self.in_queue.put_nowait((self.socket, data, addr))

	def connection_lost(self, exc):
		self.in_queue.put_nowait((None, exc))

