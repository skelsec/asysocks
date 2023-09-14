import asyncio


class Packetizer:
	def __init__(self, buffer_size = 65535):
		self.buffer_size = buffer_size
	
	def packetizer_control(self, *args, **kw):
		return None
	
	def flush_buffer(self):
		return b''

	def set_buffersize(self, buffer_size:int):
		self.buffer_size = buffer_size
	
	async def data_out(self, data):
		yield data

	async def data_in(self, data):
		yield data

class StreamPacketizer:
	def __init__(self, buffer_size = 65535):
		self.buffer_size = buffer_size
		self.buffer = b''
		self.stream_ended = asyncio.Event()
		self.__read_lock = asyncio.Lock()
		self.data_incoming_evt = asyncio.Event()

	async def terminate(self):
		pass
	
	def packetizer_control(self, *args, **kw):
		return None
	
	def flush_buffer(self):
		return b''

	def set_buffersize(self, buffer_size:int):
		self.buffer_size = buffer_size

	async def readuntil(self, end = b'\n'):
		if self.stream_ended.is_set():
			raise Exception('Stream ended!')

		if self.__read_lock.locked():
			raise Exception('A read operation is already in progress!')
		
		async with self.__read_lock:
			while self.buffer.find(end) == -1:
				await self.data_incoming_evt.wait()
				self.data_incoming_evt.clear()
			
			m = self.buffer.find(end) + len(end)
			res = self.buffer[:m]
			self.buffer = self.buffer[m:]
			return res


	async def readexactly(self, n):
		if self.stream_ended.is_set():
			raise Exception('Stream ended!')

		if n < 0:
			raise Exception('N must be >0')
		if n == 0:
			return b''
		if self.__read_lock.locked():
			raise Exception('A read operation is already in progress!')
		
		async with self.__read_lock:
			
			while len(self.buffer) < n:
				await self.data_incoming_evt.wait()
				self.data_incoming_evt.clear()
			
			res = self.buffer[:n]
			self.buffer = self.buffer[n:]
			return res

	async def read(self, n = -1):
		if self.stream_ended.is_set():
			raise Exception('Stream ended!')

		if self.__read_lock.locked():
			raise Exception('A read operation is already in progress!')
		async with self.__read_lock:
			while len(self.buffer) == 0 or len(self.buffer) < n:
				await self.data_incoming_evt.wait()
				self.data_incoming_evt.clear()
			if n == -1:
				n = len(self.buffer)
			res = self.buffer[:n]
			self.buffer = self.buffer[n:]
			return res
	
	async def data_out(self, data):
		yield data

	async def data_in(self, data):
		if self.stream_ended.is_set() and data != b'':
			raise Exception('More data incoming after stream has ended!')
		if data == b'':
			self.stream_ended.set()
		else:
			self.buffer += data
			self.data_incoming_evt.set()
