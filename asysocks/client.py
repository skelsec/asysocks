
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
		self.proxytask_in = None
		self.proxytask_out = None
		self.proxy_stopped_evt = None
	
	async def terminate(self):
		if self.proxy_stopped_evt is not None:
			self.proxy_stopped_evt.set()
		if self.proxytask_in is not None:
			self.proxytask_in.cancel()
		if self.proxytask_out is not None:
			self.proxytask_out.cancel()


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
			logger.debug('')
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
			logger.debug('')
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
					await out_queue.put((None, Exception('proxy_queue_out endpoint disconncted gracefully!')))
					return
				await out_queue.put((data, None))
		except asyncio.CancelledError:
			await out_queue.put((None, Exception('proxy_queue_out got cancelled!')))
			return
		except Exception as e:
			logger.debug('')
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
			await asyncio.wait_for(remote_writer.drain(), timeout = self.target.timeout)
			rep, err = await asyncio.wait_for(SOCKS4Reply.from_streamreader(remote_reader), timeout = self.target.timeout)
			if err is not None:
				raise err

			if rep is None:
				raise Exception('Socks server failed to reply to CONNECT request!')

			if rep.CD != SOCKS4CDCode.REP_GRANTED:
				raise Exception('Socks server returned error on CONNECT! %s' % rep.CD.value)
			logger.debug('[SOCKS4] Channel opened')
			return True, None
		except Exception as e:
			logger.debug('run_socks4')
			return False, e          

	async def run_socks5(self, remote_reader, remote_writer):
		"""
		Does the intial "handshake" instructing the remote server to set up the connection to the endpoint
		"""
		logger.debug('[SOCKS5] invoked')
		
		methods = [SOCKS5Method.NOAUTH]
		if self.credentials is not None:
			return False, Exception('SOCKS5 authentication is not supported for the moment')
			#add additional methods here
		
		try:
			
			nego = SOCKS5Nego.from_methods(methods)
			logger.debug('[SOCKS5] Sending negotiation command to server @ %s:%d' % remote_writer.get_extra_info('peername'))
			remote_writer.write(nego.to_bytes())
			await asyncio.wait_for(
				remote_writer.drain(), 
				timeout = self.target.timeout
			)

			rep_nego = await asyncio.wait_for(
				SOCKS5NegoReply.from_streamreader(remote_reader), 
				timeout = self.target.timeout
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
				timeout=self.target.timeout
			)

			rep = await asyncio.wait_for(
				SOCKS5Reply.from_streamreader(remote_reader), 
				timeout=self.target.timeout
			)
			if rep.REP != SOCKS5ReplyType.SUCCEEDED:
				#logger.info('Failed to connect to proxy %s! Server replied: %s' % (self.proxy_writer.get_extra_info('peername'), repr(rep.REP)))
				raise Exception('Socks5 remote end failed to connect to target! Reson: %s' % rep.REP.name)
				
			
			logger.debug('[SOCKS5] Server @ %s:%d successfully set up the connection to the endpoint! ' % remote_writer.get_extra_info('peername'))
			return True, None
		except Exception as e:
			logger.debug('[SOCKS5] Error in run_socks5')
			return False, e

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
			logger.debug('Failed to connect to SOCKS server!')
			raise
		
		if self.target.version == SocksServerVersion.SOCKS4:
			_, err = await self.run_socks4(remote_reader, remote_writer)
			if err is not None:
				raise err

		elif self.target.version == SocksServerVersion.SOCKS5:
			_, err = await self.run_socks5(remote_reader, remote_writer)
			if err is not None:
				raise err
		else:
			raise Exception('Unknown SOCKS version!')
		
		logger.debug('[handle_client] Starting proxy...')
		self.proxy_stopped_evt = asyncio.Event()
		self.proxytask_in = asyncio.create_task(
			SOCKSClient.proxy_stream(
				reader, 
				remote_writer, 
				self.proxy_stopped_evt , 
				buffer_size = self.target.buffer_size,
				timeout = self.target.endpoint_timeout
			)
		)
		self.proxytask_out = asyncio.create_task(
			SOCKSClient.proxy_stream(
				remote_reader, 
				writer, 
				self.proxy_stopped_evt, 
				buffer_size = self.target.buffer_size,
				timeout = self.target.endpoint_timeout
			)
		)
		logger.debug('[handle_client] Proxy started!')
		await self.proxy_stopped_evt.wait()
		logger.debug('[handle_client] Proxy stopped!')
		self.proxytask_in.cancel()
		self.proxytask_out.cancel()

	async def handle_queue(self):
		logger.debug('[queue] Connecting to socks server...')
		#connecting to socks server
		remote_writer = None
		try:
			remote_reader, remote_writer = await asyncio.wait_for(
				asyncio.open_connection(
					self.target.server_ip, 
					self.target.server_port
				),
				timeout = self.target.timeout
			)

			logger.debug('[queue] Connected to socks server!')

			if self.target.version == SocksServerVersion.SOCKS4:
				_, err = await self.run_socks4(remote_reader, remote_writer)
				if err is not None:
					raise err

			elif self.target.version == SocksServerVersion.SOCKS5:
				_, err = await self.run_socks5(remote_reader, remote_writer)
				if err is not None:
					raise err
			else:
				raise Exception('[queue] Unknown SOCKS version!')
			
			logger.debug('[queue] Starting proxy...')
			
			self.proxy_stopped_evt = asyncio.Event()
			self.proxytask_in = asyncio.create_task(
				SOCKSClient.proxy_queue_in(
					self.comms.in_queue, 
					remote_writer, 
					self.proxy_stopped_evt, 
					buffer_size = self.target.buffer_size
				)
			)
			self.proxytask_out = asyncio.create_task(
				SOCKSClient.proxy_queue_out(
					self.comms.out_queue, 
					remote_reader, 
					self.proxy_stopped_evt, 
					buffer_size = self.target.buffer_size, 
					timeout=self.target.endpoint_timeout
				)
			)
			logger.debug('[queue] Proxy started!')
			await self.proxy_stopped_evt.wait()
			logger.debug('[queue] Proxy stopped!')
			self.proxytask_in.cancel()
			self.proxytask_out.cancel()
		
		except Exception as e:
			await self.comms.in_queue.put((None, e))
			await self.comms.out_queue.put((None,e))
		
		finally:
			if remote_writer is not None:
				remote_writer.close()


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
		