from pyodidewsnet.client import WSNetworkTCP
import asyncio

class WSNETNetwork:
	@staticmethod
	async def open_connection(host, port):
		out_queue = asyncio.Queue()
		in_queue = asyncio.Queue()
		closed_event = asyncio.Event()

		client = WSNetworkTCP(host, int(port), in_queue, out_queue)
		_, err = await client.run()
		if err is not None:
			raise err
			
		writer = WSNETWriter(out_queue, closed_event)
		reader = WSNETReader(in_queue, closed_event)
		await writer.run()
		await reader.run()
		
		return reader, writer

class WSNETWriter:
	def __init__(self, out_queue, closed_event):
		self.out_queue = out_queue
		self.closed_event = closed_event

	def write(self, data):
		self.out_queue.put_nowait(data)

	def close(self):
		self.out_queue.put_nowait(None)
		self.closed_event.set()

	async def drain(self):
		return

	async def run(self):
		return


class WSNETReader:
	def __init__(self, in_queue, closed_event):
		self.in_queue = in_queue
		self.closed_event = closed_event
		self.buffer = b''
		self.data_in_evt = None

	async def __handle_in(self):
		while True:
			res, err = await self.in_queue.get()
			if err is not None:
				self.buffer += res
				self.data_in_evt.set()
				self.closed_event.set()
				
				return
			self.buffer += res
			self.data_in_evt.set()

	async def run(self):
		self.data_in_evt = asyncio.Event()
		self.handle_task = asyncio.create_task(self.__handle_in())
		await asyncio.sleep(0) #making sure prev line fired

	async def read(self, n = -1):
		try:
			if self.closed_event.is_set():
				return b''

			while len(self.buffer) == 0:
				self.data_in_evt.clear()
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
			if self.closed_event.is_set():
				raise Exception('Pipe broken!')

			if n < 1:
				raise Exception('Readexactly must be a positive integer!')

			while len(self.buffer) >= n:
				self.data_in_evt.clear()
				await self.data_in_evt.wait()
			
			temp = self.buffer[:n]
			self.buffer = self.buffer[n:]
			return temp

		except Exception as e:
			print(e)

	async def readuntil(self, pattern):
		try:
			if self.closed_event.is_set():
				raise Exception('Pipe broken!')

			while self.buffer.find(pattern) == -1:
				self.data_in_evt.clear()
				await self.data_in_evt.wait()
			
			end = self.buffer.find(pattern)+len(pattern)
			temp = self.buffer[:end]
			self.buffer = self.buffer[end:]
			return temp

		except Exception as e:
			print(e)

	async def readline(self):
		return await self.readuntil(b'\n')
