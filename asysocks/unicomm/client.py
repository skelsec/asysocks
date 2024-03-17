import asyncio
import copy
import random
import base64
from asysocks.unicomm.protocol.http import HTTPProxyAuthRequiredException, HTTPResponse, HTTPProxyAuthFailed
from asysocks.unicomm.protocol.socks4a import SOCKS4ARequest, SOCKS4AReply, SOCKS4ACDCode
from asysocks.unicomm.protocol.socks5 import SOCKS5Method, SOCKS5Nego, SOCKS5NegoReply, SOCKS5PlainAuth, \
	SOCKS5AuthFailed, SOCKS5PlainAuthReply, SOCKS5ReplyType, SOCKS5Request, SOCKS5Reply, \
	SOCKS5ServerErrorReply


from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.common.proxy import UniProxyProto, UniProxyTarget
from asysocks.unicomm.common.packetizers import Packetizer
from asysocks.unicomm.common.packetizers.ssl import PacketizerSSL
from asysocks.unicomm.common.connection import UniConnection
from asysocks.unicomm import logger


class ProxyChainError(Exception):
	def __init__(self, innerexception, message="Something failed setting up the proxy chain! See innerexception for more details"):
		self.innerexception = innerexception
		self.message = message
		super().__init__(self.message)


class UniClient:
	def __init__(self, target:UniTarget, packetizer:Packetizer):
		self.target = target
		self.packetizer = packetizer
		self.bind_progress_evt = asyncio.Event()
		self.http_auth_ctx = None

	async def run_http(self, proxy:UniProxyTarget, remote_reader:asyncio.StreamReader, remote_writer:asyncio.StreamWriter, timeout:int = None, http_auth_ctx:str = None):		
		try:
			logger.debug('[HTTP] Opening channel to %s:%s' % (proxy.endpoint_ip, proxy.endpoint_port))
			connect_cmd = 'CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n' % (proxy.endpoint_ip, proxy.endpoint_port, proxy.endpoint_ip, proxy.endpoint_port)
			connect_cmd = connect_cmd.encode()

			
			if http_auth_ctx is None:
				remote_writer.write(connect_cmd + b'\r\n')
				await asyncio.wait_for(remote_writer.drain(), timeout = timeout)
				
				resp, err = await HTTPResponse.from_streamreader(remote_reader, timeout=timeout)
				if err is not None:
					raise err

				if resp.status == 200:
					logger.debug('[HTTP] Server succsessfully connected!')
					return True, http_auth_ctx, None
			
				elif resp.status == 407:
					logger.debug('[HTTP] Server proxy auth required!')

					if proxy.credential is None:
						raise Exception('HTTP proxy auth required but no credential set!')
					
					auth_type = resp.headers_upper.get('PROXY-AUTHENTICATE', None)
					if auth_type is None:
						raise Exception('HTTP proxy requires authentication, but requested auth type could not be determined')
					
					auth_type, _ = auth_type.split(' ', 1)
					logger.debug('HTTP proxy requires %s auth' % auth_type)
					http_auth_ctx = auth_type.upper()

					return False, http_auth_ctx, HTTPProxyAuthRequiredException()
			
			elif http_auth_ctx == 'BASIC':
				auth_data = base64.b64encode(('%s:%s' % (proxy.credential.username, proxy.credential.password) ).encode() )
				auth_connect = connect_cmd + b'Proxy-Authorization: Basic ' + auth_data + b'\r\n'
				remote_writer.write(auth_connect + b'\r\n')
				await asyncio.wait_for(remote_writer.drain(), timeout = timeout)

				resp, err = await HTTPResponse.from_streamreader(remote_reader, timeout=timeout)
				if err is not None:
					raise err

				if resp.status == 200:
					logger.debug('[HTTP] Server proxy auth succsess!')
					return True, http_auth_ctx, None
					
				else:
					raise HTTPProxyAuthFailed() #raise Exception('Proxy auth failed!')
				
			else:
				raise Exception('HTTP proxy requires %s authentication, but it\'s not implemented' % http_auth_ctx)


		except Exception as e:
			logger.debug('run_http')
			return False, None, e

	async def run_socks4a(self, proxy:UniProxyTarget, remote_reader:asyncio.StreamReader, remote_writer:asyncio.StreamWriter, timeout:int = None):
		"""
		Does the intial "handshake" instructing the remote server to set up the connection to the endpoint
		"""
		try:
			logger.debug('[SOCKS4A %s:%s] Opening channel to %s:%s (target)' % (proxy.server_ip, proxy.server_port, proxy.endpoint_ip, proxy.endpoint_port))
			req = SOCKS4ARequest.from_target(proxy)
			if proxy.credential is not None and proxy.credential.username is not None:
				req.USERID = proxy.credential.username
			remote_writer.write(req.to_bytes())
			await asyncio.wait_for(remote_writer.drain(), timeout = timeout)
			rep, err = await asyncio.wait_for(SOCKS4AReply.from_streamreader(remote_reader), timeout = timeout)
			if err is not None:
				raise err

			if rep is None:
				raise Exception('Socks server failed to reply to CONNECT request!')

			if rep.CD != SOCKS4ACDCode.REP_GRANTED:
				raise Exception('Socks server returned error on CONNECT! %s' % rep.CD.value)
			logger.debug('[SOCKS4A] Channel opened')
			return True, None
		except Exception as e:
			logger.debug('run_socks4a')
			return False, e
	
	async def run_socks5(self, proxy:UniProxyTarget, remote_reader:asyncio.StreamReader, remote_writer:asyncio.StreamWriter, timeout:int = None):
		"""
		Does the intial "handshake" instructing the remote server to set up the connection to the endpoint
		"""
		sname = proxy.get_sname()
		tname = proxy.get_tname()
		methods = [SOCKS5Method.NOAUTH]
		if proxy.credential is not None and proxy.credential.username is not None and proxy.credential.password is not None:
			methods.append(SOCKS5Method.PLAIN)
			#methods = [SOCKS5Method.PLAIN]
		try:
			nego = SOCKS5Nego.from_methods(methods)
			logger.debug('[SOCKS5 %s][SETUP] Sending negotiation command to server' % sname)
			remote_writer.write(nego.to_bytes())
			await asyncio.wait_for(
				remote_writer.drain(), 
				timeout = timeout
			)

			rep_nego = await asyncio.wait_for(
				SOCKS5NegoReply.from_streamreader(remote_reader), 
				timeout = timeout
			)
			logger.debug(
				'[SOCKS5 %s] Got negotiation reply! Server choosen auth type: %s' % (sname, rep_nego.METHOD.name)
			)
			
			if rep_nego.METHOD == SOCKS5Method.PLAIN:
				if proxy.credential is None or proxy.credential.username is None or proxy.credential.password is None:
					raise Exception('SOCKS5 %s] server requires PLAIN authentication, but no credentials were supplied!' % sname)
				
				logger.debug('[SOCKS5 %s]Preforming plaintext auth' % sname)
				remote_writer.write(
					SOCKS5PlainAuth.construct(
						proxy.credential.username, 
						proxy.credential.password
					).to_bytes()
				)
				await asyncio.wait_for(
					remote_writer.drain(), 
					timeout=None
				)
				rep_data = await asyncio.wait_for(
					remote_reader.read(2),
					timeout = timeout
				)

				if rep_data == b'':
					raise SOCKS5AuthFailed() #raise Exception('Plaintext auth failed! Bad username or password')

				rep_nego = SOCKS5PlainAuthReply.from_bytes(rep_data)

				if rep_nego.STATUS != SOCKS5ReplyType.SUCCEEDED:
					raise SOCKS5AuthFailed() #raise Exception('Plaintext auth failed! Bad username or password')

			elif rep_nego.METHOD == SOCKS5Method.GSSAPI:
				raise Exception('[SOCKS5 %s] server requires GSSAPI authentication, but it\'s not supported at the moment' % sname)

			logger.debug('[SOCKS5 %s] Opening channel to %s' % (sname, tname))
			
			if proxy.only_auth is True:
				return True, None

			remote_writer.write(
				SOCKS5Request.from_target(
					proxy
				).to_bytes()
			)
			await asyncio.wait_for(
				remote_writer.drain(), 
				timeout=timeout
			)

			rep = await asyncio.wait_for(
				SOCKS5Reply.from_streamreader(remote_reader), 
				timeout=timeout
			)
			if rep.REP != SOCKS5ReplyType.SUCCEEDED:
				logger.info('[SOCKS5 %s] remote end failed to connect to proxy! Reson: %s' % (sname, rep.REP.name))
				raise SOCKS5ServerErrorReply(rep.REP)
			
			if proxy.protocol.name.startswith('SERVER') is False:
				logger.debug('[SOCKS5 %s] Successfully set up the connection to the endpoint %s ' % (sname,tname))
				return True, None
			
			logger.debug('[SOCKS5 %s] BIND first set completed, port %s available!' % (sname , rep.BIND_PORT))
			#bind in progress, waiting for a second reply to notify us that the remote endpoint connected back.
			
			self.bind_port = rep.BIND_PORT
			self.bind_progress_evt.set() #notifying that the bind port is now available on the socks server to be used
			if proxy.only_bind is True:
				return True, None

			rep = await asyncio.wait_for(
				SOCKS5Reply.from_streamreader(remote_reader), 
				timeout=timeout
			)

			if rep.REP != SOCKS5ReplyType.SUCCEEDED:
				logger.info('[SOCKS5 %s] remote end failed to connect to proxy! Reson: %s' % (sname, rep.REP.name))
				raise SOCKS5ServerErrorReply(rep.REP)

			return True, None

		except Exception as e:
			logger.debug('[SOCKS5 %s] Error in run_socks5 %s' % (sname, e))
			return False, e
	
	async def create_link(self):
		remote_writer = None
		remote_reader = None

		try:
			logger.debug('[handle_client] Client connected!')

			if len(self.target.proxies) > 1:
				logger.debug('Start chaining...')

			for _ in range(3, 0 , -1): #this is for HTTP auth...
				if remote_writer is not None:
					remote_writer.close()
				
				try:
					proxy = copy.deepcopy(self.target.proxies[0])
					if len(self.target.proxies) == 1:
						proxy.endpoint_ip = self.target.get_ip_or_hostname()
						proxy.endpoint_port = self.target.port

					if proxy.protocol == UniProxyProto.CLIENT_WSNET:
						from asysocks.network.wsnet import WSNETNetwork
						remote_reader, remote_writer = await WSNETNetwork.open_connection(
							proxy.endpoint_ip,
							proxy.endpoint_port,
							proxy.wsnet_reuse,
						)
					elif proxy.protocol == UniProxyProto.CLIENT_WSNETTEST:
						from asysocks.network.wsnet import WSNETNetworkTest
						remote_reader, remote_writer = await WSNETNetworkTest.open_connection(
							proxy.endpoint_ip,
							proxy.endpoint_port,
							proxy.wsnet_reuse,
						)
					elif proxy.protocol in [UniProxyProto.CLIENT_WSNETDIRECT, UniProxyProto.CLIENT_SSL_WSNETDIRECT]:
						from asysocks.network.wsnetdirect import WSNetworkDirect
						remote_reader, remote_writer = await WSNetworkDirect.open_connection(
							proxy.server_ip,
							proxy.server_port,
							proxy.protocol,
							proxy.endpoint_ip,
							proxy.endpoint_port,
							proxy.wsnet_reuse,
						)
					elif proxy.protocol in [UniProxyProto.CLIENT_WSNETWS, UniProxyProto.CLIENT_SSL_WSNETWS]:
						from asysocks.network.wsnetws import WSNETNetworkWS
						remote_reader, remote_writer = await WSNETNetworkWS.open_connection(
							proxy.endpoint_ip,
							proxy.endpoint_port,
							proxy.server_ip,
							proxy.server_port,
							proxy.protocol,
							proxy.agentid,
							proxy.timeout,
						)
						if remote_reader is None:
							raise remote_writer
					elif proxy.protocol == UniProxyProto.CLIENT_CUSTOM:
						proxyconnection, err = proxy.customproxyfactory()
						if err is not None:
							raise err

						remote_reader, remote_writer, err = await proxyconnection.connect(
							proxy.endpoint_ip,
							proxy.endpoint_port,
							proxy.protocol,
						)
						if err is not None:
							raise err
						
					else:
						remote_reader, remote_writer = await asyncio.wait_for(
							asyncio.open_connection(
								proxy.server_ip, 
								proxy.server_port,
								ssl=proxy.ssl_ctx,
							),
							timeout = proxy.timeout
						)
						logger.debug('Connected to socks server!')

				except:
					logger.debug('Failed to connect to SOCKS server!')
					raise
					
				try:
					for i, proxy in enumerate(self.target.proxies):
						proxy = copy.deepcopy(proxy)
						if i == len(self.target.proxies)-1:
							proxy.endpoint_ip = self.target.get_ip_or_hostname()
							proxy.endpoint_port = self.target.port

						if proxy.protocol in [UniProxyProto.CLIENT_SOCKS4, UniProxyProto.CLIENT_SSL_SOCKS4]:
							try:
								x = await asyncio.wait_for(self.run_socks4a(proxy, remote_reader, remote_writer), timeout=self.target.proxies[-1].timeout)
							except asyncio.TimeoutError:
								raise Exception('Proxy Connection establishment timeout')
							_, err = x
							if err is not None:
								if len(self.target.proxies) > 1 and i != len(self.target.proxies)-1:
									raise ProxyChainError(err)
								raise err
							continue

						elif proxy.protocol in [UniProxyProto.CLIENT_SOCKS5_TCP, UniProxyProto.CLIENT_SSL_SOCKS5_TCP]:
							try:
								x = await asyncio.wait_for(self.run_socks5(proxy, remote_reader, remote_writer), timeout=self.target.proxies[-1].timeout)
							except asyncio.TimeoutError:
								raise Exception('Proxy Connection establishment timeout')
							_, err = x
							if err is not None:
								if len(self.target.proxies) > 1 and i != len(self.target.proxies)-1:
									raise ProxyChainError(err)
								raise err
							continue
							
						elif proxy.protocol in [UniProxyProto.CLIENT_HTTP, UniProxyProto.CLIENT_SSL_HTTP]:
							try:
								x = await asyncio.wait_for(self.run_http(proxy, remote_reader, remote_writer, http_auth_ctx = self.http_auth_ctx), timeout=self.target.proxies[-1].timeout)
							except asyncio.TimeoutError:
								raise Exception('Proxy Connection establishment timeout')
							_, self.http_auth_ctx, err = x 
							if err is not None:
								if len(self.target.proxies) > 1 and i != len(self.target.proxies)-1:
									raise ProxyChainError(err)
								raise err
							continue

						elif proxy.protocol in [UniProxyProto.CLIENT_WSNET, UniProxyProto.CLIENT_WSNETWS, UniProxyProto.CLIENT_SSL_WSNETWS, UniProxyProto.CLIENT_WSNETTEST, UniProxyProto.CLIENT_CUSTOM, UniProxyProto.CLIENT_WSNETDIRECT, UniProxyProto.CLIENT_SSL_WSNETDIRECT]:
							if i != 0:
								raise Exception("WSNET only supported as the first proxy in chain!")
							continue

						else:
							raise Exception('Unknown SOCKS version! "%s"' % proxy.protocol)

					else:
						# no need to do more iterations because of HTTP at this point
						break

				except HTTPProxyAuthRequiredException:
					continue
				except:
					raise
					
			return remote_reader, remote_writer
		
		except Exception as e:
			logger.debug('[handle_client] Exception: %s' % e)
			if remote_writer is not None:
				remote_writer.close()
			raise
	
	async def open_privileged_connection(self):
		for attempt in range(10):
			try:
				# Attempt to use a lower port, incrementing if unsuccessful
				local_addr = ('0.0.0.0', random.randint(10, 1023))
				reader, writer = await asyncio.open_connection(self.target.get_ip_or_hostname(), self.target.port, local_addr=local_addr)				
				return reader, writer, None
			except PermissionError as e:
				return None, None, e
			except OSError as e:
				if e.errno == 98:  # Port already in use (Linux specific error code, adjust for your OS if necessary)
					continue  # Try again with a different port
				return None, None, e
			except Exception as e:
				return None, None, e
		return None, None, Exception("Failed to connect after 10 attempts")

	async def connect(self):
		packetizer = copy.deepcopy(self.packetizer)
		if len(self.target.proxies) > 0:
			reader, writer = await self.create_link()
			if self.target.protocol == UniProto.CLIENT_SSL_TCP:
				ssl_ctx = self.target.get_ssl_context()
				packetizer = PacketizerSSL(ssl_ctx, packetizer)
				await packetizer.do_handshake(reader, writer)

		else:
			if self.target.protocol not in [UniProto.CLIENT_SSL_TCP, UniProto.CLIENT_TCP]:
				raise Exception('Unknown protocol "%s"' % self.target.protocol)
			if self.target.use_privileged_source_port is True:
				# client should use a privileged source port
				reader, writer, err = await self.open_privileged_connection()
				if err is not None:
					raise err
			else:
				reader, writer = await asyncio.open_connection(self.target.get_ip_or_hostname(), self.target.port)

			if self.target.protocol == UniProto.CLIENT_SSL_TCP:
				ssl_ctx = self.target.get_ssl_context()
				packetizer = PacketizerSSL(ssl_ctx, packetizer)
				await packetizer.do_handshake(reader, writer)

		return UniConnection(reader, writer, packetizer)

async def amain():
	import logging

	logger.setLevel(logging.DEBUG)
	target = UniTarget()
	target.hostname = 'google.com'
	target.port = 443
	target.protocol = UniProto.CLIENT_SSL_TCP
	target.timeout = 10
	target.ssl_ctx = None
	packetizer = Packetizer()

	client = UniClient(target, packetizer)
	connection = await client.connect()
	await connection.write(b'GET / HTTP/1.1\r\nHost: google.com\r\n\r\n')
	async for data in connection.read():
		print(data)



def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()