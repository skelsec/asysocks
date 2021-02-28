

class NetworkQueue:
	def __init__(self):
		self.in_queue = None
		self.out_queue = None
		self.buffer = b''
		self.data_in_evt = None
		self.pipe_broken_evt = None


	async def run(self):
		try:
			pass

		except Exception as e:
			print(e)

	async def read(self, n = -1):
		try:
			if self.pipe_broken_evt.is_set():
				return b''

			while len(self.buffer) == 0:
				await self.data_in_evt.wait()

			if n == -1:
				temp = self.buffer
				self.buffer = b''
				return temp
			
			temp = self.buffer[:n]
			self.buffer = self.buffer[n:]
			return temp

		except Exception as e:
			print(e)

	async def readexactly(self, n):
		try:
			if self.pipe_broken_evt.is_set():
				raise Exception('Pipe broken!')

			if n < 1:
				raise Exception('Readexactly must be a positive integer!')

			while len(self.buffer) >= n:
				await self.data_in_evt.wait()
			
			temp = self.buffer[:n]
			self.buffer = self.buffer[n:]
			return temp

		except Exception as e:
			print(e)

	async def readuntil(self, pattern):
		try:
			if self.pipe_broken_evt.is_set():
				raise Exception('Pipe broken!')

			while self.buffer.find(pattern) == -1:
				await self.data_in_evt.wait()
			
			end = self.buffer.find(pattern)+len(pattern)
			temp = self.buffer[:end]
			self.buffer = self.buffer[end:]
			return temp

		except Exception as e:
			print(e)

	async def readline(self):
		return await self.readuntil(b'\n')
