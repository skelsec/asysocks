
import asyncio
import os
import traceback
from wsnet.protocol import *
import websockets
from asysocks.unicomm import logger
from asysocks.network.wsnet import WSNETWriter, WSNETReader
from asysocks.unicomm.common.proxy import UniProxyProto

class WSNetworkDirect:
	def __init__(self, server_ip, server_port, server_protocol, ip, port, in_q, out_q, reuse = False):
		self.ws_url = None
		self.ws = None
		self.ws_proxy = None
		self.server_ip = server_ip
		self.server_port = server_port
		self.server_protocol = server_protocol
		self.ip = ip
		self.port = port
		self.in_q = in_q
		self.out_q = out_q
		self.token = os.urandom(16)

		self.in_task = None
		self.out_task = None

	async def terminate(self):
		if self.in_task is not None:
			self.in_task.cancel()
		if self.out_task is not None:
			self.out_task.cancel()
		if self.ws is not None:
			await self.ws.close()
		self.ws = None

	async def __handle_in(self):
		try:
			while self.ws.open:
				try:
					data = await self.ws.recv()
					cmd = CMD.from_bytes(bytearray(data))

					#print('__handle_in %s' % cmd)
					if cmd.type == CMDType.OK:
						logger.debug('Remote end terminated the socket')
						raise Exception('Remote end terminated the socket')
					elif cmd.type == CMDType.ERR:
						logger.debug('Proxy sent error during data transmission. Killing the tunnel.')
						raise Exception('Proxy sent error during data transmission. Killing the tunnel.')

					await self.in_q.put((cmd.data, None))
				except asyncio.CancelledError:
					return
				except Exception as e:
					traceback.print_exc()
					await self.in_q.put((None, e))
					return
		except:
			traceback.print_exc()
		finally:
			await self.terminate()


	async def __handle_out(self):
		try:
			while self.ws.open:
				data = await self.out_q.get()
				#print('OUT %s' % data)
				if data is None or data == b'':
					return
				cmd = WSNSocketData(self.token, data)
				await self.ws.send(cmd.to_bytes())
		except Exception as e:
			traceback.print_exc()
			return
		finally:
			try:
				cmd = WSNOK(self.token)
				await self.ws.send(cmd.to_bytes())
			except:
				pass
			await self.terminate()
	
	async def connect(self):
		try:
			logger.debug('WSNetworkDirect connecting... %s:%s' % (self.ip, self.port))
			cmd = WSNConnect(self.token, 'TCP', self.ip, self.port)
			await self.ws.send(cmd.to_bytes())


			data = await self.ws.recv()
			cmd = CMD.from_bytes(bytearray(data))

			logger.debug('WSNetworkDirect connect reply %s' % cmd)
			if cmd.type == CMDType.CONTINUE:
				return True, None
			if cmd.type == CMDType.ERR:
				raise Exception('Connection failed, proxy sent error. Err: %s' % cmd.reason)
			raise Exception('Connection failed, expected CONTINUE, got %s' % cmd.type.value)
				
		except Exception as e:
			traceback.print_exc()
			return False, e

	async def run(self):
		try:
			if self.server_protocol == UniProxyProto.CLIENT_WSNETDIRECT:
				proto = 'ws'
			elif self.server_protocol == UniProxyProto.CLIENT_SSL_WSNETDIRECT:
				proto = 'wss'
			else:
				proto = 'ws'
			if self.server_port is None or self.server_port == '' or self.server_port == 0:
				self.server_port = 8700
			self.ws_url = '%s://%s:%s' % (proto, self.server_ip, self.server_port)
			logger.debug('WSNetworkDirect connecting to proxy server at %s' % self.ws_url)
			self.ws = await websockets.connect(self.ws_url)

			_, err = await self.connect()
			if err is not None:
				await self.in_q.put(None)
				return False, err
			
			self.in_task = asyncio.create_task(self.__handle_in())
			self.out_task = asyncio.create_task(self.__handle_out())

			return True, None
		except Exception as e:
			traceback.print_exc()
			await self.terminate()
			return False, e

	@staticmethod
	async def open_connection(server_ip, server_port, server_protocol, host, port, wsnet_reuse = False):
		out_queue = asyncio.Queue()
		in_queue = asyncio.Queue()
		closed_event = asyncio.Event()

		client = WSNetworkDirect(server_ip, server_port, server_protocol, host, int(port), in_queue, out_queue, wsnet_reuse)
		_, err = await client.run()
		if err is not None:
			raise err
			
		writer = WSNETWriter(out_queue, closed_event)
		reader = WSNETReader(in_queue, closed_event)
		await writer.run()
		await reader.run()
		
		return reader, writer