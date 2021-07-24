from wsnet.pyodide.client import WSNetworkTCP
import asyncio

# This code only works properly in the conditions met in this specific library.
# If you want to copy it to your project please make sure that you 
# NEVER under any circumstances use the reader in multiple separate corutines at the same time
# else you gonna have a bad time.
# 

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
		await asyncio.sleep(0)
		return

	async def run(self):
		return


class WSNETReader:
	def __init__(self, in_queue, closed_event):
		self.wsnet_reader_type = None
		self.in_queue = in_queue
		self.closed_event = closed_event
		self.buffer = b''
		self.data_in_evt = []
		self.err = None

	async def __handle_in(self):
		while True:
			res, self.err = await self.in_queue.get()
			if self.err is not None:
				if res is not None:
					self.buffer += res
					if len(self.data_in_evt) != 0:
						evt = self.data_in_evt.pop()
						evt.set()
				self.closed_event.set()
				return

			self.buffer += res
			if len(self.data_in_evt) != 0:
				evt = self.data_in_evt.pop()
				evt.set()

	async def run(self):
		self.handle_task = asyncio.create_task(self.__handle_in())
		await asyncio.sleep(0) #making sure prev line fired

	async def read(self, n = -1):
		try:
			#print('read')
			if self.closed_event.is_set():
				return b''

			if len(self.buffer) == 0:
				evt = asyncio.Event()
				self.data_in_evt.append(evt)
				await evt.wait()


			temp = self.buffer[:n]
			self.buffer = self.buffer[n:]
			#print('read ret %s' % temp)
			return temp

		except Exception as e:
			#print(e)
			self.closed_event.set()
			raise

	async def readexactly(self, n):
		try:
			if self.closed_event.is_set():
				raise Exception('Pipe broken!')

			if n < 1:
				raise Exception('Readexactly must be a positive integer!')

			while len(self.buffer) < n:
				#print('readexactly waiting...')
				evt = asyncio.Event()
				self.data_in_evt.append(evt)
				await evt.wait()
			
			#print('self.buffer %s' % self.buffer)
			temp = self.buffer[:n]
			self.buffer = self.buffer[n:]
			#print('readexactly ret %s' % temp)
			return temp

		except Exception as e:
			#print(e)
			self.closed_event.set()
			raise

	async def readuntil(self, pattern):
		try:
			if self.closed_event.is_set():
				raise Exception('Pipe broken!')

			while self.buffer.find(pattern) == -1:
				evt = asyncio.Event()
				self.data_in_evt.append(evt)
				await evt.wait()
			
			end = self.buffer.find(pattern)+len(pattern)
			temp = self.buffer[:end]
			self.buffer = self.buffer[end:]
			#print('readuntil ret %s' % temp)
			return temp

		except Exception as e:
			#print(e)
			self.closed_event.set()
			raise

	async def readline(self):
		return await self.readuntil(b'\n')
