import asyncio
import copy
import traceback
import base64

from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.common.proxy import UniProxyProto, UniProxyTarget
from asysocks.unicomm.common.packetizers import Packetizer, StreamPacketizer
from asysocks.unicomm.common.packetizers.ssl import PacketizerSSL
from asysocks.unicomm.server import UniServer, UniConnection




class HTTPConnectionSettings(RunningServerSettings):
	def __init__(self, server_settings: ServerSettings, gssapi: SPNEGORelay, log_q: asyncio.Queue = None):
		RunningServerSettings.__init__(self, server_settings, gssapi, log_q)

class HTTPServerConnection:
	def __init__(self, settings:HTTPConnectionSettings, reader:asyncio.StreamReader, writer:asyncio.StreamWriter, client_ip:str, client_port:int):
		self.client_ip = client_ip
		self.client_port = client_port
		self.settings = settings
		self.gssapi = settings.gssapi
		self.ntlm = self.gssapi.authentication_contexts['NTLMSSP - Microsoft NTLM Security Support Provider']
		self.reader = reader
		self.writer = writer
		self.unauthorized_status = 401
		self.unauthorized_reason = 'Unauthorized'
		self.authorization_key = 'WWW-Authenticate'
		if self.settings.server_settings.isproxy is True:
			self.unauthorized_status = 407
			self.unauthorized_reason = 'Proxy Authentication Required'
			self.authorization_key = 'Proxy-Authenticate'
	
	async def log_async(self, level, msg):
		if self.settings.log_q is not None:
			src = 'HTTPCON-%s:%s' % (self.client_ip, self.client_port)
			await self.settings.log_q.put((src, level, msg))
		else:
			logger.log(level, msg)
	
	async def run(self):
		try:
			while True:
				req, err = await HTTPRequest.from_streamreader(self.reader, timeout = 10)
				if err is not None:
					raise err

				if 'AUTHORIZATION' not in req.headers_upper:
					response = HTTPResponse()
					response.version = 'HTTP/1.1'
					response.status = self.unauthorized_status
					response.reason = self.unauthorized_reason
					response.headers = {
						'Server': 'ngix',
						'Connection': 'close',
						self.authorization_key: 'NTLM',
						'Content-Length': '0'
					}
					await self.log_async(1, "Sending response: %s" % response.to_bytes())
					self.writer.write(response.to_bytes())
					await self.writer.drain()
					self.writer.close()
					return
				
				authdata_raw = req.headers_upper['AUTHORIZATION']
				if authdata_raw.startswith('NTLM') is False:
					await self.log_async(1, 'Authdata doesnt seem to be NTLM! %s' % authdata)
					return
				
				authdata = base64.b64decode(authdata_raw[5:])
				res, to_continue, err = await self.ntlm.authenticate_relay_server(authdata)
				if err is not None:
					raise err
				
				if to_continue is True:
					if res is not None:
						response = HTTPResponse()
						response.version = 'HTTP/1.1'
						response.status = self.unauthorized_status
						response.reason = self.unauthorized_reason
						response.headers = {
							'Server': 'ngix',
							'Connection': 'keep-alive',
							self.authorization_key: 'NTLM %s' % base64.b64encode(res).decode(),
							'Content-Length': '0'
						}
						await self.log_async(1, "Sending response: %s" % response.to_bytes())
						self.writer.write(response.to_bytes())
						await self.writer.drain()
						continue
					else:
						response = HTTPResponse()
						response.version = 'HTTP/1.1'
						response.status = 404
						response.reason = 'Not Found'
						response.headers = {
							'Server': 'ngix',
							'Connection': 'keep-alive',
							'Content-Length': '0'
						}
						self.writer.write(response.to_bytes())
						await self.writer.drain()
						return

		except Exception as e:
			await self.log_async(1, "Client connection error! %s" % e)




class HTTPServerSocket(ServerBase):
	"""
	"""
	def __init__(self, settings:HTTPConnectionSettings, server_queue: asyncio.Queue, log_q: asyncio.Queue):
		ServerBase.__init__(self, settings, server_queue, log_q, log_source_name = 'HTTP-TCP')
		self.ip = settings.server_settings.ip
		self.port = settings.server_settings.port

		
	async def handle_incoming(self, client):
		"""
		Reads data bytes from the socket and dispatches it to the incoming queue
		"""
		try:
			while not self.shutdown_evt.is_set():	
				data = await client.reader.read(65535)
				await client.in_queue.put((data, None))
		except Exception as e:
			await client.in_queue.put((None, e))
			return
		
	async def handle_outgoing(self, client):
		"""
		Reads data bytes from the outgoing queue and dispatches it to the socket
		"""
		try:
			while not self.shutdown_evt.is_set():
				data = await client.out_queue.get()
				client.writer.write(data)
				await client.writer.drain()
		except asyncio.CancelledError:
			#the SMB connection is terminating
			return
			
		except Exception as e:
			await self.log_async(99, '[TCP] handle_outgoing %s' % str(e))
		
	async def handle_client(self, connection:UniConnection):
		out_task = None
		in_task = None
		try:
			raddr = ''
			rport = 0
			#raddr, rport = writer.get_extra_info('peername')
			#await self.log_async(20, '[TCP] Client connected from %s:%s' % (raddr, rport))
			
			connection_settings = copy.deepcopy(self.settings)
			connection_settings.log_q = self.log_q
			connection_settings.gssapi.setup(self.log_q)
			server = HTTPServerConnection(connection_settings, connection, raddr, rport)
			await self.server_queue.put(('http', server))
			await server.run()
			await self.log_async(10, 'Connection terminated, closing client! %s:%s' % (raddr, rport))
		except Exception as e:
			traceback.print_exc()
			await self.log_async(99, '[TCP] handle_client %s' % str(e))
		finally:
			if out_task is not None:
				out_task.cancel()
			if in_task is not None:
				in_task.cancel()
		
		
	#async def listen(self):
	#	try:
	#		proxies = []
	#		target = UniTarget(self.ip, self.port, UniProto.SERVER_TCP, proxies=proxies)
	#		packetizer = StreamPacketizer()
	#		server = UniServer(target, packetizer)
	#		await self.log_async(10, 'TCP Server in listening state')
	#		async for connection in server.serve():
	#			print('Client connected!')
	#			asyncio.create_task(self.handle_client(connection))
	#
	#		await self.log_async(10, 'TCP server terminated')
	#	except Exception as e:
	#		await self.log_async(99, '[TCP] listen %s' % str(e))
			
	async def run(self):
		await self.listen()