from wsnet.operator.networkproxy import WSNetworkWS
from asysocks.common.constants import SocksServerVersion
import asyncio
import traceback
from asysocks import logger

# This code only works properly in the conditions met in this specific library.
# If you want to copy it to your project please make sure that you 
# NEVER under any circumstances use the reader in multiple separate corutines at the same time
# else you gonna have a bad time.
# 

class WSNETNetworkWS:
	@staticmethod
	async def open_connection(target_host, target_port, host, port, proto, agentid = None, timeout = None):
		try:
			out_queue = asyncio.Queue()
			in_queue = asyncio.Queue()
			closed_event = asyncio.Event()

			proto = 'ws'
			if proto == SocksServerVersion.WSNETWSS:
				proto = 'wss'
			
			url = '%s://%s:%s/' % (proto, host, port)
			logger.debug('WSNETNetworkWS URL: %s' % url)
			logger.debug('WSNETNetworkWS AGENTID: %s' % agentid)
			agentid = bytes.fromhex(agentid)

			client = WSNetworkWS(target_host, target_port, url, in_queue, out_queue, agentid)
			_, err = await asyncio.wait_for(client.run(), timeout)
			if err is not None:
				raise err
			writer = WSNETWriter(out_queue, closed_event, client)
			reader = WSNETReader(in_queue, closed_event)
			await writer.run()
			await reader.run()
			
			return reader, writer
		except Exception as e:
			print('W')
			traceback.print_exc()
			return None, e

class WSNETWriter:
	def __init__(self, out_queue, closed_event, client):
		self.out_queue = out_queue
		self.closed_event = closed_event
		self.client = client

	def write(self, data):
		#print('THIS IS DATA: %s' % data)
		self.out_queue.put_nowait(data)

	def close(self):
		self.out_queue.put_nowait(None)
		self.closed_event.set()
		asyncio.create_task(self.client.terminate())

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
		try:
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

		except asyncio.CancelledError:
			return

		except Exception as e:
			raise e

		finally:
			self.closed_event.set()
			for evt in self.data_in_evt:
				evt.set()


	async def run(self):
		self.handle_task = asyncio.create_task(self.__handle_in())
		await asyncio.sleep(0) #making sure prev line fired

	async def read(self, n = -1):
		try:
			#print('read')
			if self.closed_event.is_set():
				data = self.buffer
				#print('read ret %s' % data)
				self.buffer = b''
				return data

			if len(self.buffer) == 0:
				evt = asyncio.Event()
				self.data_in_evt.append(evt)
				await evt.wait()


			temp = self.buffer[:n]
			self.buffer = self.buffer[n:]
			#print('read ret %s' % temp)
			return temp

		
		except asyncio.CancelledError:
			return

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

		except asyncio.CancelledError:
			return

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
		
		except asyncio.CancelledError:
			return

		except Exception as e:
			#print(e)
			self.closed_event.set()
			raise

	async def readline(self):
		return await self.readuntil(b'\n')
