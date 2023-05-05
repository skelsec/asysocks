# this is experimental!
import asyncio
import copy
import ssl
import platform
from asysocks.unicomm.protocol.socks5 import SOCKS5Method, SOCKS5Nego, SOCKS5NegoReply, SOCKS5PlainAuth, \
	SOCKS5AuthFailed, SOCKS5PlainAuthReply, SOCKS5ReplyType, SOCKS5Request, SOCKS5Reply, \
	SOCKS5ServerErrorReply


from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.common.proxy import UniProxyProto, UniProxyTarget
from asysocks.unicomm.common.packetizers import Packetizer, StreamPacketizer
from asysocks.unicomm.common.packetizers.ssl import PacketizerSSL
from asysocks.unicomm.common.connection import UniConnection, UniUDPConnection
from asysocks.unicomm import logger
from asysocks.unicomm.client import UniClient
from asysocks.unicomm.protocol.server.udp import UDPProtocol
import ipaddress


class ProxyChainError(Exception):
	def __init__(self, innerexception, message="Something failed setting up the proxy chain! See innerexception for more details"):
		self.innerexception = innerexception
		self.message = message
		super().__init__(self.message)


class UniServer:
	def __init__(self, target:UniTarget, packetizer:Packetizer, bindtype:int = None):
		self.target = target
		self.bindtype = bindtype
		self.packetizer = packetizer
		self.bind_progress_evt = asyncio.Event()
		self.connection_queue = asyncio.Queue()
	
	async def run_socks5(self, proxy:UniProxyTarget, connection:UniConnection, timeout:int = None):
		"""
		Does the intial "handshake" instructing the remote server to set up the connection to the endpoint
		"""
		stream_task = asyncio.create_task(connection.stream())
		sname = proxy.get_sname()
		tname = proxy.get_tname()
		methods = [SOCKS5Method.NOAUTH]
		if proxy.credential is not None and proxy.credential.username is not None and proxy.credential.password is not None:
			methods.append(SOCKS5Method.PLAIN)
			#methods = [SOCKS5Method.PLAIN]
		try:
			nego = SOCKS5Nego.from_methods(methods)
			logger.debug('[SOCKS5 %s][SETUP] Sending negotiation command to server' % sname)
			await connection.write(nego.to_bytes())

			rep_nego = await asyncio.wait_for(
				SOCKS5NegoReply.from_streamreader(connection.packetizer), 
				timeout = timeout
			)
			logger.debug(
				'[SOCKS5 %s] Got negotiation reply! Server choosen auth type: %s' % (sname, rep_nego.METHOD.name)
			)
			
			if rep_nego.METHOD == SOCKS5Method.PLAIN:
				if proxy.credential is None or proxy.credential.username is None or proxy.credential.password is None:
					raise Exception('SOCKS5 %s] server requires PLAIN authentication, but no credentials were supplied!' % sname)
				
				logger.debug('[SOCKS5 %s]Preforming plaintext auth' % sname)
				await connection.write(
					SOCKS5PlainAuth.construct(
						proxy.credential.username, 
						proxy.credential.password
					).to_bytes()
				)
				rep_data = await asyncio.wait_for(
					connection.packetizer.readexactly(2),
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

			await connection.write(
				SOCKS5Request.from_target(
					proxy
				).to_bytes()
			)
			rep = await asyncio.wait_for(
				SOCKS5Reply.from_streamreader(connection.packetizer), 
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
				SOCKS5Reply.from_streamreader(connection.packetizer), 
				timeout=timeout
			)

			if rep.REP != SOCKS5ReplyType.SUCCEEDED:
				logger.info('[SOCKS5 %s] remote end failed to connect to proxy! Reson: %s' % (sname, rep.REP.name))
				raise SOCKS5ServerErrorReply(rep.REP)
			return True, None

		except Exception as e:
			logger.debug('[SOCKS5 %s] Error in run_socks5 %s' % (sname, e))
			return False, e
		finally:
			if stream_task is not None:
				stream_task.cancel()
	
	async def create_link(self):
		remote_writer = None
		remote_reader = None

		try:
			if len(self.target.proxies) > 1:
				logger.debug('Start chaining...')
				
			if len(self.target.proxies) == 1:
				if self.target.proxies[0].protocol == UniProxyProto.SERVER_WSNET:
					from wsnet.pyodide.tcpserver import WSNetworkTCPServer
					if self.target.protocol == UniProto.SERVER_TCP:
						return await WSNetworkTCPServer(self.__handle_connection, self.target.get_ip_or_hostname(), self.target.port, bindtype = 1, reuse_ws = True).run()
					elif self.target.protocol == UniProto.SERVER_SSL_TCP:
						return await WSNetworkTCPServer(self.__handle_connection_ssl, self.target.get_ip_or_hostname(), self.target.port, bindtype = 1, reuse_ws = True).run()
					else:
						raise Exception('WSNET unimplemented proto %s' % self.target.protocol)
				elif self.target.proxies[0].protocol in [UniProxyProto.SERVER_SOCKS5_TCP, UniProxyProto.CLIENT_SSL_SOCKS5_TCP, UniProxyProto.SERVER_SOCKS5_UDP, UniProxyProto.SERVER_SSL_SOCKS5_UDP]:
					#### SOCKS TCP BIND only allows one (1) connection at a time!!!!!! This is a limitation in the RFC
					try:
						ttarget = UniTarget(self.target.proxies[0].server_ip, self.target.proxies[0].server_port, protocol=UniProto.CLIENT_TCP)							
						client = UniClient(ttarget, StreamPacketizer())
						connection = await client.connect()
						_, err = await asyncio.wait_for(self.run_socks5(self.target.proxies[0], connection), timeout=self.target.proxies[-1].timeout)
						if err is not None:
							raise err
						if self.target.protocol == UniProto.SERVER_TCP:
							connection.change_packetizer(copy.deepcopy(self.packetizer))
							await self.connection_queue.put(connection)
							return connection, None
						elif self.target.protocol == UniProto.SERVER_SSL_TCP:
							ssl_ctx = self.target.get_ssl_context(ssl.PROTOCOL_TLS_SERVER)
							packetizer = PacketizerSSL(ssl_ctx, packetizer)
							await packetizer.do_handshake(connection.packetizer, connection, server_side=True)
							connection = UniConnection(connection.packetizer, connection, packetizer)
							await self.connection_queue.put(connection)
							return connection, None

					except asyncio.TimeoutError:
						raise Exception('Proxy Connection establishment timeout')
				else:
					raise Exception("Unsupported proxy protocol %s" % self.target.proxies[0].protocol)
			else:
				raise NotImplementedError()
				client_target = self.target.get_preproxy()
				client = UniClient(client_target, Packetizer())
				connection = await client.connect()

			raise Exception('Should not be here!')		
		except Exception as e:
			logger.exception('[create_link]')
			if remote_writer is not None:
				remote_writer.close()
			raise

	async def __handle_connection(self, reader, writer):
		packetizer = copy.deepcopy(self.packetizer)
		connection = UniConnection(reader, writer, packetizer)
		await self.connection_queue.put(connection)
		await connection.closed_evt.wait()

	async def __handle_connection_ssl(self, reader, writer):
		ssl_ctx = None
		try:
			packetizer = copy.deepcopy(self.packetizer)
			ssl_ctx = self.target.get_ssl_context(ssl.PROTOCOL_TLS_SERVER)
			packetizer = PacketizerSSL(ssl_ctx, packetizer)
			await packetizer.do_handshake(reader, writer, server_side=True)
			connection = UniConnection(reader, writer, packetizer)
			await self.connection_queue.put(connection)
			await connection.closed_evt.wait()
		finally:
			if ssl_ctx is not None:
				del ssl_ctx


	async def start_llmnr_server(self):
		try:
			in_queue = asyncio.Queue()
			if platform.system() == 'Emscripten':
				from wsnet.pyodide.udpserver import WSNetworkUDPServer
				protofactory = lambda: UDPProtocol(in_queue)
				wsnetserver = WSNetworkUDPServer(protofactory, '0.0.0.0', 5355, bindtype = 2, reuse_ws = False)
				servertransport, serverproto, err = await wsnetserver.run()
				if err is not None:
					raise err
				return servertransport, serverproto, None
			
			import socket
			import struct
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			sock.bind(('', 5355))
			group = ipaddress.ip_address('224.0.0.252').packed
			mreq = struct.pack('4sL', group, socket.INADDR_ANY)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.setblocking(False)
			protofactory = lambda: UDPProtocol(in_queue)
			servertransport, serverproto = await asyncio.get_event_loop().create_datagram_endpoint(protofactory, sock=sock)
			return servertransport, serverproto, None
		except Exception as e:
			return None, None, e
		
	async def start_mdns_server(self):
		try:
			in_queue = asyncio.Queue()
			if platform.system() == 'Emscripten':
				from wsnet.pyodide.udpserver import WSNetworkUDPServer
				protofactory = lambda: UDPProtocol(in_queue)
				wsnetserver = WSNetworkUDPServer(protofactory, '0.0.0.0', 5353, bindtype = 4, reuse_ws = False)
				servertransport, serverproto, err = await wsnetserver.run()
				if err is not None:
					raise err
				return servertransport, serverproto, None
			import socket
			import struct
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			sock.bind(('224.0.0.251', 5353))
			group = ipaddress.ip_address('224.0.0.251').packed
			mreq = struct.pack("=4sl", group, socket.INADDR_ANY)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.setblocking(False)
			protofactory = lambda: UDPProtocol(in_queue)
			servertransport, serverproto = await asyncio.get_event_loop().create_datagram_endpoint(protofactory, sock=sock)
			return servertransport, serverproto, None
		except Exception as e:
			return None, None, e
		
	async def start_nbtns_server(self):
		try:
			in_queue = asyncio.Queue()
			if platform.system() == 'Emscripten':
				from wsnet.pyodide.udpserver import WSNetworkUDPServer
				protofactory = lambda: UDPProtocol(in_queue)
				wsnetserver = WSNetworkUDPServer(protofactory, '0.0.0.0', 137, bindtype = 3, reuse_ws = False)
				servertransport, serverproto, err = await wsnetserver.run()
				if err is not None:
					raise err
				return servertransport, serverproto, None
			import socket
			sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			sock.bind(('0.0.0.0', 137))
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
			sock.setblocking(False)
			protofactory = lambda: UDPProtocol(in_queue)
			servertransport, serverproto = await asyncio.get_event_loop().create_datagram_endpoint(protofactory, sock=sock)
			return servertransport, serverproto, None
		except Exception as e:
			return None, None, e
		


	async def serve(self):
		if len(self.target.proxies) > 0:
			server, err = await self.create_link()
			if err is not None:
				raise err
			while not server.closed_evt.is_set():
				connection = await self.connection_queue.get()
				yield connection
			
		else:
			if self.target.protocol in [UniProto.SERVER_TCP, UniProto.SERVER_SSL_TCP]:
				if self.target.protocol == UniProto.SERVER_TCP:
					server = await asyncio.start_server(self.__handle_connection, self.target.get_ip_or_hostname(), self.target.port)
				elif self.target.protocol == UniProto.SERVER_SSL_TCP:
					server = await asyncio.start_server(self.__handle_connection_ssl, self.target.get_ip_or_hostname(), self.target.port)
				while server.is_serving():
					connection = await self.connection_queue.get()
					yield connection

			elif self.target.protocol == UniProto.SERVER_UDP:
				if self.bindtype == 2:
					transport, protocol, err = await self.start_llmnr_server()
					if err is not None:
						raise err
				
				elif self.bindtype == 3:
					transport, protocol, err = await self.start_nbtns_server()
					if err is not None:
						raise err

				elif self.bindtype == 4:
					transport, protocol, err = await self.start_mdns_server()
					if err is not None:
						raise err

				else:
					raise Exception('Unsupported bindtype %s' % self.bindtype)

				while True:
					socket, data, addr = await protocol.in_queue.get()
					yield UniUDPConnection(socket, data, addr)

			else:
				raise Exception('Unknown protocol "%s"' % self.target.protocol)

			

async def amain():
	import logging

	logger.setLevel(logging.DEBUG)
	proxy = UniProxyTarget()
	proxy.server_ip = '127.0.0.1'
	proxy.server_port = 1080
	proxy.protocol = UniProxyProto.SERVER_SOCKS5_TCP
	target = UniTarget('0.0.0.0', 9999, UniProto.SERVER_TCP, proxies=[proxy])
	packetizer = Packetizer()

	server = UniServer(target, packetizer)
	async for connection in server.serve():
		print('Client connected!')
		async for data in connection.read():
			print(data)




def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()