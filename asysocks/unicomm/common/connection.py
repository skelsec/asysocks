import ssl
import asyncio
from asysocks.unicomm.common.packetizers import Packetizer, StreamPacketizer
from asysocks.unicomm.common.packetizers.ssl import PacketizerSSL

class UniConnection:
	def __init__(self, reader:asyncio.StreamReader, writer:asyncio.StreamWriter, packetizer:Packetizer):
		self.reader = reader
		self.writer = writer
		self.packetizer = packetizer
		self.packetizer_task = None
		self.closing = False
		self.closed_evt = asyncio.Event()

	async def __aenter__(self):
		return self

	async def __aexit__(self, exc_type, exc, tb):
		await self.close()

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


class UniUDPConnection:
	def __init__(self, socket, data, addr):
		self.socket = socket
		self.data = data
		self.addr = addr