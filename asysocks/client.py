
import asyncio

from asysocks import logger
from asysocks.common.constants import SocksServerVersion, SocksCommsMode
from asysocks.protocol.socks4 import SOCKS4Request, SOCKS4Reply, SOCKS4CDCode
from asysocks.protocol.socks5 import SOCKS5Method, SOCKS5Nego, SOCKS5NegoReply, SOCKS5Request, SOCKS5Reply, SOCKS5ReplyType


class SOCKSClient:
	def __init__(self, comms, target, credentials = None):
		self.target = target
		self.comms = comms
		self.credentials = credentials
		self.server_task = None
	
	async def terminate(self):
		return

	@staticmethod
	async def proxy_stream(in_stream, out_stream, proxy_stopped_evt, buffer_size = 4096, timeout = None):
		try:
			while True:
				data = await asyncio.wait_for(
					in_stream.read(buffer_size),
					timeout = timeout
				)
				if data == b'':
					logger.debug('Stream channel broken!')
					return
				out_stream.write(data)
				await out_stream.drain()
		except asyncio.CancelledError:
			return
		except:
			logger.exception('')
		finally:
			proxy_stopped_evt.set()

	@staticmethod
	async def proxy_queue_in(in_queue, writer, proxy_stopped_evt, buffer_size = 4096):
		try:
			while True:
				data = await in_queue.get()
				if data is None:
					logger.debug('proxy_queue_in client disconncted!')
					return
				writer.write(data)
				await writer.drain()
		except asyncio.CancelledError:
			return
		except:
			logger.exception('')
		finally:
			proxy_stopped_evt.set()
			try:
				writer.close()
			except:
				pass

	@staticmethod
	async def proxy_queue_out(out_queue, reader, proxy_stopped_evt, buffer_size = 4096, timeout = None):
		try:
			while True:
				data = await asyncio.wait_for(
					reader.read(buffer_size),
					timeout = timeout
				)
				if data == b'':
					logger.debug('proxy_queue_out endpoint disconncted!')
					await out_queue.put((None, Exception('proxy_queue_out endpoint disconncted!')))
					return
				await out_queue.put((data, None))
		except asyncio.CancelledError:
			return
		except Exception as e:
			logger.exception('')
			try:
				await out_queue.put((None, e))
			except:
				pass
		finally:
			proxy_stopped_evt.set()
			

	async def run_socks4(self, remote_reader, remote_writer):
		"""
		Does the intial "handshake" instructing the remote server to set up the connection to the endpoint
		"""
		try:
			#logger.debug('[SOCKS4] Requesting new channel from remote socks server')
			logger.debug('[SOCKS5] Opening channel to %s:%s' % (self.target.endpoint_ip, self.target.endpoint_port))
			req = SOCKS4Request.from_target(self.target)
			remote_writer.write(req.to_bytes())
			await asyncio.wait_for(remote_writer.drain(), timeout = int(self.target.timeout))
			rep = await SOCKS4Reply.from_streamreader(remote_reader, timeout = self.target.timeout)

			if rep is None:
				raise Exception('Socks server failed to reply to CONNECT request!')

			if rep.CD != SOCKS4CDCode.REP_GRANTED:
				raise Exception('Socks server returned error on CONNECT! %s' % rep.CD.value)
			logger.debug('[SOCKS4] Channel opened')
		except:
			logger.exception('run_socks4')          

	async def run_socks5(self, remote_reader, remote_writer):
		"""
		Does the intial "handshake" instructing the remote server to set up the connection to the endpoint
		"""
		logger.debug('[SOCKS5] invoked')
		
		methods = [SOCKS5Method.NOAUTH]
		if self.credentials is not None:
			raise Exception('SOCKS5 authentication is not supported for the moment')
			#add additional methods here
		
		try:
			
			nego = SOCKS5Nego.from_methods(methods)
			logger.debug('[SOCKS5] Sending negotiation command to server @ %s:%d' % remote_writer.get_extra_info('peername'))
			remote_writer.write(nego.to_bytes())
			await asyncio.wait_for(
				remote_writer.drain(), 
				timeout = int(self.target.timeout)
			)

			rep_nego = await asyncio.wait_for(
				SOCKS5NegoReply.from_streamreader(remote_reader), 
				timeout = int(self.target.timeout)
			)
			logger.debug(
				'[SOCKS5] Got negotiation reply from from %s! Server choosen auth type: %s' % 
				(remote_writer.get_extra_info('peername'), rep_nego.METHOD.name)
			)
			#logger.debug('Got negotiation reply from %s: %s' % (self.proxy_writer.get_extra_info('peername'), repr(rep_nego)))
			
			if rep_nego.METHOD == SOCKS5Method.PLAIN:
				raise Exception('SOCKS5 server requires authentication, but it\'s not supported at the moment')
				#logger.debug('Preforming plaintext auth to %s:%d' % self.proxy_writer.get_extra_info('peername'))
				#self.proxy_writer.write(SOCKS5PlainAuth.construct(self.target.proxy.username, self.target.proxy.secret).to_bytes())
				#await asyncio.wait_for(self.proxy_writer.drain(), timeout=int(self.target.proxy.timeout))
				#rep_auth_nego = await asyncio.wait_for(SOCKS5NegoReply.from_streamreader(self.proxy_reader), timeout = int(self.target.proxy.timeout))

				#if rep_auth_nego.METHOD != SOCKS5Method.NOAUTH:
				#	raise Exception('Failed to connect to proxy %s:%d! Authentication failed!' % self.proxy_writer.get_extra_info('peername'))

			logger.debug('[SOCKS5] Opening channel to %s:%s' % (self.target.endpoint_ip, self.target.endpoint_port))
			logger.debug('[SOCKS5] Sending connect request to SOCKS server @ %s:%d' % remote_writer.get_extra_info('peername'))
			remote_writer.write(
				SOCKS5Request.from_target(
					self.target
				).to_bytes()
			)
			await asyncio.wait_for(
				remote_writer.drain(), 
				timeout=int(self.target.timeout)
			)

			rep = await asyncio.wait_for(
				SOCKS5Reply.from_streamreader(remote_reader), 
				timeout=int(self.target.timeout)
			)
			if rep.REP != SOCKS5ReplyType.SUCCEEDED:
				#logger.info('Failed to connect to proxy %s! Server replied: %s' % (self.proxy_writer.get_extra_info('peername'), repr(rep.REP)))
				raise Exception('Socks5 remote end failed to connect to target! Reson: %s' % rep.REP.name)
			
			logger.debug('[SOCKS5] Server @ %s:%d successfully set up the connection to the endpoint! ' % remote_writer.get_extra_info('peername'))

		except:
			logger.exception('[SOCKS5] Error in run_socks5')
			raise

	async def handle_client(self, reader, writer):
		logger.debug('[handle_client] Client connected!')
		try:
			remote_reader, remote_writer = await asyncio.wait_for(
				asyncio.open_connection(
					self.target.server_ip, 
					self.target.server_port
				),
				timeout = self.target.timeout
			)
			logger.debug('Connected to socks server!')
		except:
			logger.exception('Failed to connect to SOCKS server!')
			raise
		
		if self.target.version == SocksServerVersion.SOCKS4:
			await self.run_socks4(remote_reader, remote_writer)

		elif self.target.version == SocksServerVersion.SOCKS5:
			await self.run_socks5(remote_reader, remote_writer)
		else:
			raise Exception('Unknown SOCKS version!')
		
		logger.debug('[handle_client] Starting proxy...')
		proxy_stopped_evt = asyncio.Event()
		pt_in = asyncio.create_task(
			SOCKSClient.proxy_stream(
				reader, 
				remote_writer, 
				proxy_stopped_evt , 
				buffer_size = self.target.buffer_size,
				timeout = self.target.endpoint_timeout
			)
		)
		pt_out = asyncio.create_task(
			SOCKSClient.proxy_stream(
				remote_reader, 
				writer, 
				proxy_stopped_evt, 
				buffer_size = self.target.buffer_size,
				timeout = self.target.endpoint_timeout
			)
		)
		logger.debug('[handle_client] Proxy started!')
		await proxy_stopped_evt.wait()
		logger.debug('[handle_client] Proxy stopped!')
		pt_in.cancel()
		pt_out.cancel()

	async def handle_queue(self):
		logger.debug('[queue] Connecting to socks server...')
		#connecting to socks server
		try:
			remote_reader, remote_writer = await asyncio.wait_for(
				asyncio.open_connection(
					self.target.server_ip, 
					self.target.server_port
				),
				timeout = self.target.timeout
			)

			logger.debug('[queue] Connected to socks server!')
		except:
			logger.exception('[queue] Failed to connect to SOCKS server!')
			raise


		if self.target.version == SocksServerVersion.SOCKS4:
			await self.run_socks4(remote_reader, remote_writer)

		elif self.target.version == SocksServerVersion.SOCKS5:
			await self.run_socks5(remote_reader, remote_writer)
		else:
			raise Exception('[queue] Unknown SOCKS version!')
		
		logger.debug('[queue] Starting proxy...')
		
		proxy_stopped_evt = asyncio.Event()
		pt_in = asyncio.create_task(
			SOCKSClient.proxy_queue_in(
				self.comms.in_queue, remote_writer, proxy_stopped_evt, buffer_size = self.target.buffer_size
			)
		)
		pt_out = asyncio.create_task(
			SOCKSClient.proxy_queue_out(
				self.comms.out_queue, remote_reader, proxy_stopped_evt, buffer_size = self.target.buffer_size
			)
		)
		logger.debug('[queue] Proxy started!')
		await proxy_stopped_evt.wait()
		logger.debug('[queue] Proxy stopped!')
		pt_in.cancel()
		pt_out.cancel()


	async def run(self):
		if self.comms.mode == SocksCommsMode.LISTENER:
			server = await asyncio.start_server(
				self.handle_client, 
				self.comms.listen_ip, 
				self.comms.listen_port,

			)
			logger.debug('[PROXY] Awaiting server task now...')
			await server.serve_forever()

		else:
			await self.handle_queue()
		