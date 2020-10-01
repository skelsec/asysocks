
import logging
import asyncio
import socket
import copy
import ssl
import ipaddress
from urllib.parse import urlparse

from asysocks.common.constants import SocksServerVersion, SocksCommsMode
from asysocks.protocol.http import HTTPRequest
from asysocks.protocol.socks4 import SOCKS4Request, SOCKS4Reply, SOCKS4CDCode
from asysocks.protocol.socks5 import SOCKS5Command, SOCKS5AddressType, SOCKS5Method, SOCKS5Nego, SOCKS5NegoReply, SOCKS5Request, SOCKS5Reply, SOCKS5ReplyType, SOCKS5PlainAuth, SOCKS5PlainAuthReply, SOCKS5ServerErrorReply, SOCKS5AuthFailed


srvlogger = logging.getLogger('PROXYSERVER')
handler = logging.StreamHandler()
formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
srvlogger.addHandler(handler)
srvlogger.setLevel(logging.INFO)

class ProxyMonitorSSL:
	def __init__(self, monitor, client_ssl_ctx = None, destination_ssl_ctx = None):
		self.monitor = monitor
		self.client_ssl_ctx = client_ssl_ctx
		self.destination_ssl_ctx = destination_ssl_ctx

		self.stop_evt = asyncio.Event()
		self.client_ssl_ok_evt = asyncio.Event()
		self.destination_ssl_ok_evt = asyncio.Event()
		self.client_tls_obj = None
		self.client_tls_in_buff = None
		self.client_tls_out_buff = None
		self.destination_tls_obj = None
		self.destination_tls_in_buff = None
		self.destination_tls_out_buff = None

		self.__client_ssl_in_q = asyncio.Queue()
		self.__destination_ssl_in_q = asyncio.Queue()

		self.c2d_ssl_task = None
		self.d2c_ssl_task = None
		self.dest_task = None
		self.client_task = None

	async def __read_ssl_record(self, raw_in_q, ssl_in_q):
		try:
			buffer = b''
			length = None
			while not self.stop_evt.is_set():
				
				if length is None and len(buffer) >= 6:
					length = int.from_bytes(buffer[3:5], byteorder = 'big', signed = False)
				
				if length is not None and len(buffer) >= length + 5:
					print('LB raw %s' % len(buffer[:length+5]))
					await ssl_in_q.put(buffer[:length+5])
					buffer = buffer[length+5:]
					length = None
					continue
				
				data = await raw_in_q.get()
				if data == b'':
					await ssl_in_q.put(b'')
					return
				buffer+= data
				

		except asyncio.CancelledError:
			return

		except Exception as e:
			print('__read_ssl_record %s' % e)
			await ssl_in_q.put(b'')

		#finally:
		#	self.stop_evt.set()

	async def __do_ssl_handshake_cli(self, ssl_ctx, in_q, out_q):
		try:
			tls_in_buff = ssl.MemoryBIO()
			tls_out_buff = ssl.MemoryBIO()
			tls_obj = ssl_ctx.wrap_bio(tls_in_buff, tls_out_buff, server_side=False, server_hostname = self.monitor.dst_hostname)
			print('################## %s' % self.monitor.dst_ip)

			ctr = 0
			while not self.stop_evt.is_set():
				ctr += 1
				print('DST Performing handshake!')
				try:
					tls_obj.do_handshake()
				except ssl.SSLWantReadError:
					print('DST want %s' % ctr)
					while True:
						client_hello = tls_out_buff.read()
						if client_hello != b'':
							print('DST client_hello %s' % len(client_hello))
							await out_q.put(client_hello)
						else:
							break
					
					print('DST wating server hello %s' % ctr)
					server_hello = await in_q.get()
					print('DST server_hello %s' % len(server_hello))
					tls_in_buff.write(server_hello)

					continue
				except:
					raise
				else:
					print('DST handshake ok %s' % ctr)
					#server_fin = tls_out_buff.read()
					#print('DST server_fin %s ' %  server_fin)
					#await out_q.put(server_fin)
					break			

			return tls_in_buff, tls_out_buff, tls_obj, None

		except Exception as e:
			print(e)
			return None, None, None, e

	async def __do_ssl_handshake_srv(self, ssl_ctx, in_q, out_q):
		try:
			tls_in_buff = ssl.MemoryBIO()
			tls_out_buff = ssl.MemoryBIO()
			tls_obj = ssl_ctx.wrap_bio(tls_in_buff, tls_out_buff, server_side=True)
			ctr = 0
			while not self.stop_evt.is_set():
				ctr += 1
				#print('wating client hello %s' % ctr)
				client_hello = await in_q.get()
				#print('client_hello %s' % len(client_hello))
				tls_in_buff.write(client_hello)

				#print('Performing handshake!')
				try:
					tls_obj.do_handshake()
				except ssl.SSLWantReadError:
					#print('want %s' % ctr)
					while True:
						server_hello = tls_out_buff.read()
						if server_hello != b'':
							#print('server_hello %s' % len(server_hello))
							await out_q.put(server_hello)
						else:
							break
					continue
				except:
					raise
				else:
					#print('handshake ok %s' % ctr)
					while True:
						server_fin = tls_out_buff.read()
						if server_fin != b'':
							await out_q.put(server_fin)
						else:
							break

					break			

			return tls_in_buff, tls_out_buff, tls_obj, None

		except Exception as e:
			#print(e)
			return None, None, None, e


	async def __client_ssl_endpoint(self):
		try:
			self.client_tls_in_buff, self.client_tls_out_buff, self.client_tls_obj, err = await self.__do_ssl_handshake_srv(self.client_ssl_ctx, self.__client_ssl_in_q, self.monitor.d2c_out)
			if err is not None:
				raise err
			print('CLIENT Handshake OK!')
			self.client_ssl_ok_evt.set()
			await self.destination_ssl_ok_evt.wait()
			while not self.stop_evt.is_set():
				client_ssl_data = await self.__client_ssl_in_q.get()
				if client_ssl_data == b'':
					print('Connection terminated')
					return
				self.client_tls_in_buff.write(client_ssl_data)
				while True:
					try:
						client_data = self.client_tls_obj.read()
					except ssl.SSLWantReadError:
						break
					print('client_data %s' % client_data)
					self.destination_tls_obj.write(client_data)

				while True:
					client_ssl_data = self.destination_tls_out_buff.read()
					if client_ssl_data == b'':
						break
					await self.monitor.c2d_out.put(client_ssl_data)

		except Exception as e:
			print('CLIENT error: %s' % e)
			return None, None, None, e
		
		finally:
			self.stop_evt.set()
			self.client_ssl_ok_evt.set()
			self.destination_ssl_ok_evt.set()
			await self.monitor.c2d_out.put(b'')
			self.c2d_ssl_task.cancel()
			self.d2c_ssl_task.cancel()
			self.dest_task.cancel()

	async def __destination_ssl_endpoint(self):
		try:
			self.destination_tls_in_buff, self.destination_tls_out_buff, self.destination_tls_obj, err = await self.__do_ssl_handshake_cli(self.client_ssl_ctx, self.__destination_ssl_in_q, self.monitor.c2d_out)
			if err is not None:
				raise err
			self.destination_ssl_ok_evt.set()
			await self.client_ssl_ok_evt.wait()
			print('DST Handshake OK!')
			while not self.stop_evt.is_set():
				destination_ssl_data = await self.__destination_ssl_in_q.get()
				if destination_ssl_data == b'':
					print('Connection terminated')
					return
				print('destination_ssl_data : %s' % len(destination_ssl_data))
				self.destination_tls_in_buff.write(destination_ssl_data)
				while True:
					try:
						destination_data = self.destination_tls_obj.read()
					except ssl.SSLWantReadError:
						break
					print('destination_data %s' % destination_data)
					self.client_tls_obj.write(destination_data)
					
				while True:
					destination_ssl_data = self.client_tls_out_buff.read()
					if destination_ssl_data == b'':
						break
					await self.monitor.d2c_out.put(destination_ssl_data)

		except Exception as e:
			print(type(e))
			print('DST error: %s' % e)
			return None, None, None, e

		finally:
			self.stop_evt.set()
			self.client_ssl_ok_evt.set()
			self.destination_ssl_ok_evt.set()
			await self.monitor.d2c_out.put(b'')
			self.c2d_ssl_task.cancel()
			self.d2c_ssl_task.cancel()
			self.client_task.cancel()


	
	async def intercept(self):
		self.c2d_ssl_task = asyncio.create_task(self.__read_ssl_record(self.monitor.c2d_in, self.__client_ssl_in_q))
		self.d2c_ssl_task = asyncio.create_task(self.__read_ssl_record(self.monitor.d2c_in, self.__destination_ssl_in_q))
		self.dest_task = asyncio.create_task(self.__destination_ssl_endpoint())
		self.client_task = asyncio.create_task(self.__client_ssl_endpoint())
		await self.stop_evt.wait()


class ProxyMonitor:
	def __init__(self, client_ip, client_port, dst_ip, dst_port, module):
		self.client_ip = client_ip
		self.client_port = client_port
		self.dst_ip = dst_ip
		self.dst_hostname = None
		self.dst_port = dst_port
		self.module = module
		self.logline_c2d = '[%s][MONITOR][%s:%s -> %s:%s]' % (self.module, self.client_ip, self.client_port, self.dst_ip, self.dst_port)
		self.logline_d2c = '[%s][MONITOR][%s:%s -> %s:%s]' % (self.module, self.dst_ip, self.dst_port, self.client_ip, self.client_port)

		self.c2d_in = asyncio.Queue()
		self.c2d_out = asyncio.Queue()
		self.d2c_in = asyncio.Queue()
		self.d2c_out = asyncio.Queue()

	def set_hostname(self, hostname):
		#for SNI support on SSL
		self.dst_hostname = hostname

	async def __justlog_c2d(self, stop_evt):
		try:
			while not stop_evt.is_set():
				data = await self.c2d_in.get()
				print(data)
				srvlogger.info(self.logline_c2d + str(data))
				await self.c2d_out.put(data)
				if data == b'':
					return
		except Exception as e:
			print(e)
		finally:
			stop_evt.set()

	async def __justlog_d2c(self, stop_evt):
		try:
			while not stop_evt.is_set():
				data = await self.d2c_in.get()
				print(data)
				srvlogger.info(self.logline_d2c + str(data))
				await self.d2c_out.put(data)
				if data == b'':
					return
		except Exception as e:
			print(e)
		finally:
			stop_evt.set()

	async def just_log(self):
		stop_evt = asyncio.Event()
		asyncio.create_task(self.__justlog_c2d(stop_evt))
		asyncio.create_task(self.__justlog_d2c(stop_evt))
		await stop_evt.wait()
			


class SOCKSServer:
	def __init__(self, listen_ip, listen_port, ssl_ctx = None, client_timeout = 10, buffer_size = 10240, supported_protocols = ['SOCKS4', 'SOCKS5', 'HTTP'], monitor_dispatch_q = None):
		self.listen_ip = listen_ip
		self.listen_port = listen_port
		self.ssl_ctx = ssl_ctx
		self.client_timeout = client_timeout
		self.buffer_size = buffer_size
		self.supported_protocols = supported_protocols
		self.monitor_dispatch_q = monitor_dispatch_q

	async def __proxy(self, reader_a, writer_b, stop_evt, src_module, monitor_in_q = None, monitor_out_q = None):
		async def pi(reader, in_q, buffer_size):
			try:
				while not stop_evt.is_set():
					data = await reader_a.read(buffer_size)					
					if data == b'' or data is None:
						await in_q.put(data)
						return
					await in_q.put(data)
			except:
				return
			finally:
				stop_evt.set()
		
		try:
			if monitor_in_q is not None:
				asyncio.create_task(pi(reader_a, monitor_in_q, self.buffer_size))
				while not stop_evt.is_set():
					data = await monitor_out_q.get()
					#print('data_modded %s' % data)
					if data == b'' or data is None:
						return

					writer_b.write(data)
					await writer_b.drain()

			else:
				while not stop_evt.is_set():
					data = await reader_a.read(self.buffer_size)					
					if data == b'' or data is None:
						return

					writer_b.write(data)
					await writer_b.drain()
		except asyncio.CancelledError:
			return
		except Exception as e:
			srvlogger.debug('[%s][TCPPROXY] Connection ended. Reason: %s' % (src_module, e))
		finally:
			writer_b.close()
			stop_evt.set()

	async def handle_socks4(self, init_cmd, reader, writer):
		try:
			if init_cmd.CD == SOCKS4CDCode.REQ_CONNECT:
				srvlogger.debug('[SOCKS4] Client wants to connect to: %s:%s' % (str(init_cmd.DSTIP), init_cmd.DSTPORT))
				try:
					dst_reader, dst_writer = await asyncio.open_connection(str(init_cmd.DSTIP), init_cmd.DSTPORT)
				except Exception as e:
					srvlogger.debug('[SOCKS4] Could not connect to: %s:%s Reason: %s' % (str(init_cmd.DSTIP), init_cmd.DSTPORT, e))
					reply = SOCKS4Reply()
					reply.CD = SOCKS4CDCode.REP_FAILED
					reply.DSTPORT = init_cmd.DSTPORT
					reply.DSTIP = init_cmd.DSTIP
					writer.write(reply.to_bytes())
					await writer.drain()
					return
				else:
					srvlogger.debug('[SOCKS4] Sucsessfully connected to: %s:%s Starting TCP proxy' % (str(init_cmd.DSTIP), init_cmd.DSTPORT))
					reply = SOCKS4Reply()
					reply.CD = SOCKS4CDCode.REP_GRANTED
					reply.DSTPORT = init_cmd.DSTPORT
					reply.DSTIP = init_cmd.DSTIP
					writer.write(reply.to_bytes())
					await writer.drain()
				
				stop_evt = asyncio.Event()
				c2d_in = None
				c2d_out = None
				d2c_in = None
				d2c_out = None
				if self.monitor_dispatch_q is not None:
					rem_ip, rem_port = dst_writer.get_extra_info('peername')
					client_ip, client_port = writer.get_extra_info('peername')
					monitor = ProxyMonitor(client_ip, client_port, rem_ip, rem_port, 'SOCKS4')
					c2d_in = monitor.c2d_in
					c2d_out = monitor.c2d_out
					d2c_in = monitor.d2c_in
					d2c_out = monitor.d2c_out
					await self.monitor_dispatch_q.put(monitor)
				task_1 = asyncio.create_task(self.__proxy(reader, dst_writer, stop_evt, 'SOCKS4', c2d_in, c2d_out))
				task_2 = asyncio.create_task(self.__proxy(dst_reader, writer, stop_evt, 'SOCKS4', d2c_in, d2c_out))

				await stop_evt.wait()
				srvlogger.debug('[SOCKS4] Connection ended %s:%s' % (str(init_cmd.DSTIP), init_cmd.DSTPORT))
				task_1.cancel()
				task_2.cancel()
				return

			elif init_cmd.CD == SOCKS4CDCode.REQ_BIND:
				async def __handle_remote(dst_reader, dst_writer):
					try:
						rem_ip, rem_port = dst_writer.get_extra_info('peername')
						reply = SOCKS4Reply()
						reply.CD = SOCKS4CDCode.REP_GRANTED
						reply.DSTPORT = rem_port
						reply.DSTIP = ipaddress.IPv4Address(rem_ip)
						writer.write(reply.to_bytes())
						await writer.drain()

						stop_evt = asyncio.Event()
						task_1 = asyncio.create_task(self.__proxy(reader, dst_writer, stop_evt, 'SOCKS4'))
						task_2 = asyncio.create_task(self.__proxy(dst_reader, writer, stop_evt, 'SOCKS4'))
						await stop_evt.wait()
						print('Connection terminated')
						task_1.cancel()
						task_2.cancel()

					except Exception as e:
						print('__handle_remote %s' % e) 

				try:
					serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					serversocket.bind((str(init_cmd.DSTIP), 0))
					serversocket.listen(1)
					serversocket_ip, serversocket_port = serversocket.getsockname()
					reply = SOCKS4Reply()
					reply.CD = SOCKS4CDCode.REP_GRANTED
					reply.DSTPORT = serversocket_port
					reply.DSTIP = ipaddress.IPv4Address(serversocket_ip)
					writer.write(reply.to_bytes())
					await writer.drain()
					
					await asyncio.start_server(__handle_remote, sock=serversocket, backlog = 1) #TODO: this will constantly server bc there is no way to terminate this FIX!!!
				except Exception as e:
					reply = SOCKS4Reply()
					reply.CD = SOCKS4CDCode.REP_FAILED
					reply.DSTPORT = init_cmd.DSTPORT
					reply.DSTIP = init_cmd.DSTIP
					writer.write(reply.to_bytes())
					await writer.drain()
					return			
			else:
				raise Exception('Unknown client request! %s' % init_cmd.CD)

		except Exception as e:
			import traceback
			traceback.print_exc()
			print('handle_socks4 %s' % e)

	async def handle_socks5(self, init_cmd, reader, writer):
		try:
			#TODO: currently no auth is supported, add auth functionality!
			srvlogger.debug('[SOCKS5] Authentication supported by the client %s' % (','.join([x.name for x in init_cmd.METHODS])))
			if SOCKS5Method.NOAUTH not in init_cmd.METHODS:
				reply = SOCKS5NegoReply.construct(SOCKS5Method.NOTACCEPTABLE)
				writer.write(reply.to_bytes())
				await writer.drain()
				return
			
			reply = SOCKS5NegoReply.construct(SOCKS5Method.NOAUTH)
			writer.write(reply.to_bytes())
			await writer.drain()
			
			
			req = await asyncio.wait_for(SOCKS5Request.from_streamreader(reader), timeout = self.client_timeout)

			if req.CMD == SOCKS5Command.CONNECT:
				srvlogger.debug('[SOCKS5] Client wants to connect to: %s:%s' % (str(req.DST_ADDR), req.DST_PORT))
				try:
					dst_reader, dst_writer = await asyncio.open_connection(str(req.DST_ADDR), req.DST_PORT)
				except Exception as e:
					srvlogger.debug('[SOCKS5] Could not connect to: %s:%s Reason: %s' % (str(req.DST_ADDR), req.DST_PORT, e))
					reply = SOCKS5Reply.construct(SOCKS5ReplyType.FAILURE,req.DST_ADDR, req.DST_PORT) #TODO: support more error types to let the client know what exscatly went wrong
					writer.write(reply.to_bytes())
					await writer.drain()
					return
				else:
					srvlogger.debug('[SOCKS5] Sucsessfully connected to: %s:%s Starting TCP proxy' % (str(req.DST_ADDR), req.DST_PORT))
					reply = SOCKS5Reply.construct(SOCKS5ReplyType.SUCCEEDED, req.DST_ADDR, req.DST_PORT)
					writer.write(reply.to_bytes())
					await writer.drain()
				
				stop_evt = asyncio.Event()
				c2d_in = None
				c2d_out = None
				d2c_in = None
				d2c_out = None
				if self.monitor_dispatch_q is not None:
					rem_ip, rem_port = dst_writer.get_extra_info('peername')
					client_ip, client_port = writer.get_extra_info('peername')
					monitor = ProxyMonitor(client_ip, client_port, rem_ip, rem_port, 'SOCKS5')
					if req.ATYP == SOCKS5AddressType.DOMAINNAME:
						monitor.set_hostname(str(req.DST_ADDR))
					await self.monitor_dispatch_q.put(monitor)
					c2d_in = monitor.c2d_in
					c2d_out = monitor.c2d_out
					d2c_in = monitor.d2c_in
					d2c_out = monitor.d2c_out

				task_1 = asyncio.create_task(self.__proxy(reader, dst_writer, stop_evt, 'SOCKS5', c2d_in, c2d_out))
				task_2 = asyncio.create_task(self.__proxy(dst_reader, writer, stop_evt, 'SOCKS5', d2c_in, d2c_out))

				await stop_evt.wait()
				srvlogger.debug('[SOCKS5] Connection ended %s:%s' % (str(req.DST_ADDR), req.DST_PORT))
				task_1.cancel()
				task_2.cancel()
				return

			elif req.CMD == SOCKS5Command.BIND:
				srvlogger.debug('[SOCKS5] Client wants to BIND to: %s:%s' % (str(req.DST_ADDR), req.DST_PORT))
				async def __handle_remote(dst_reader, dst_writer):
					try:
						rem_ip, rem_port = dst_writer.get_extra_info('peername')
						srvlogger.debug('[SOCKS5] Client BIND server get a connection from: %s:%s Notifying client...' % (str(rem_ip), rem_port))
						
						reply = SOCKS5Reply.construct(SOCKS5ReplyType.SUCCEEDED , ipaddress.ip_address(rem_ip), rem_port)
						writer.write(reply.to_bytes())
						await writer.drain()

						srvlogger.debug('[SOCKS5] Client BIND starting TCP proxy %s:%s' % (str(rem_ip), rem_port))
						stop_evt = asyncio.Event()
						task_1 = asyncio.create_task(self.__proxy(reader, dst_writer, stop_evt, 'SOCKS5'))
						task_2 = asyncio.create_task(self.__proxy(dst_reader, writer, stop_evt, 'SOCKS5'))
						await stop_evt.wait()
						srvlogger.debug('[SOCKS5] Client BIND connection ended %s:%s' % (str(rem_ip), rem_port))
						task_1.cancel()
						task_2.cancel()

					except Exception as e:
						srvlogger.exception('[SOCKS5] Client BIND error')

				try:
					if req.ATYP == SOCKS5AddressType.IP_V4:
						serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						serversocket.bind((str(req.DST_ADDR), 0))
					elif req.ATYP == SOCKS5AddressType.IP_V6:
						serversocket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
						serversocket.bind((str(req.DST_ADDR), 0))
					elif req.ATYP == SOCKS5AddressType.DOMAINNAME: #not sure abt this...
						serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						serversocket.bind((str(req.DST_ADDR), 0))

					serversocket.listen(1)
					serversocket_ip, serversocket_port = serversocket.getsockname()
					reply = SOCKS5Reply.construct(SOCKS5ReplyType.SUCCEEDED , ipaddress.ip_address(serversocket_ip), serversocket_port)
					writer.write(reply.to_bytes())
					await writer.drain()
					
					await asyncio.start_server(__handle_remote, sock=serversocket, backlog = 1) #TODO: this will constantly server bc there is no way to terminate this FIX!!!
				except Exception as e:
					srvlogger.debug('[SOCKS5] Error! Could not bind to: %s:%s Reason: %s' % (str(req.DST_ADDR), req.DST_PORT, e))
					reply = SOCKS5Reply.construct(SOCKS5ReplyType.FAILURE , req.DST_ADDR, req.port)
					writer.write(reply.to_bytes())
					await writer.drain()
					return			
				

			elif req.CMD == SOCKS5Command.UDP_ASSOCIATE:
				srvlogger.debug('[SOCKS5] Error! Client requested UDP Associate, but it is not implemented!')
				raise Exception('UDP assoc requested, but is not implemented!')
			else:
				raise Exception('Client requested something that was not understood. %s' % req.CMD)


		except Exception as e:
			srvlogger.exception('[SOCKS5] Generic error: %s' % (e))
			#print('handle_socks5 %s' % e)

	async def handle_http_connect(self, init_cmd, reader, writer):
		try:
			#TODO: there is not authentication implemented currently, fix!
			#TODO: not intercepting SSL
			if init_cmd.method.upper() != 'CONNECT':
				raise Exception('Unknown request type! %s' % init_cmd.method)
			
			#URI should be in HOST:PORT format
			host, port = init_cmd.uri.split(':')
			port = int(port)
			srvlogger.debug('[HTTPCONNECT] Client wants to connect to: %s:%s' % (host, port))
			try:
				dst_reader, dst_writer = await asyncio.open_connection(host, port)
			except Exception as e:
				srvlogger.debug('[HTTPCONNECT] Could not connect to %s:%s. Reason: %s' % (host, port, e))
				fail = b'HTTP/1.1 500 Error\r\n\r\n'
				writer.write(fail)
				await writer.drain()
				return
			else:
				srvlogger.debug('[HTTPCONNECT] Sucsessfully connected to %s:%s. Starting tcp proxy.' % (host, port))
				ok = b'HTTP/1.1 200 OK\r\n\r\n'
				writer.write(ok)
				await writer.drain()
				
			stop_evt = asyncio.Event()
			c2d_in = None
			c2d_out = None
			d2c_in = None
			d2c_out = None
			if self.monitor_dispatch_q is not None:
				rem_ip, rem_port = dst_writer.get_extra_info('peername')
				client_ip, client_port = writer.get_extra_info('peername')
				monitor = ProxyMonitor(client_ip, client_port, rem_ip, rem_port, 'HTTPCONNECT')
				monitor.set_hostname(host)
				await self.monitor_dispatch_q.put(monitor)
				c2d_in = monitor.c2d_in
				c2d_out = monitor.c2d_out
				d2c_in = monitor.d2c_in
				d2c_out = monitor.d2c_out

			task_1 = asyncio.create_task(self.__proxy(reader, dst_writer, stop_evt, 'HTTPCONNECT', c2d_in, c2d_out))
			task_2 = asyncio.create_task(self.__proxy(dst_reader, writer, stop_evt, 'HTTPCONNECT', d2c_in, d2c_out))

			await stop_evt.wait()
			srvlogger.debug('[HTTPCONNECT] Connection ended @ %s:%s.' % (host, port))
			task_1.cancel()
			task_2.cancel()
			return


		except Exception as e:
			srvlogger.exception('[HTTP] Generic error: %s' % (e))

	async def handle_http_generic(self, init_cmd, reader, writer):
		try:
			#TODO: there is not authentication implemented currently, fix!
			o = urlparse(init_cmd.uri)
			host = o.hostname
			port = o.port
			if port is None or port == '':
				port = 80 if o.scheme.lower() == 'http' else 443
				
			try:
				dst_reader, dst_writer = await asyncio.open_connection(host, port)
			except Exception as e:
				srvlogger.debug('[HTTP] Could not connect to %s:%s. Reason: %s' % (host, port, e))
				fail = b'HTTP/1.1 500 Error\r\n\r\n'
				writer.write(fail)
				await writer.drain()
				return
				
			c_cmd = copy.deepcopy(init_cmd)
			c_cmd.uri = o.path + o.query

			data = None
			monitor = None
			if self.monitor_dispatch_q is not None:
				rem_ip, rem_port = dst_writer.get_extra_info('peername')
				client_ip, client_port = writer.get_extra_info('peername')
				monitor = ProxyMonitor(client_ip, client_port, rem_ip, rem_port, 'HTTPCONNECT')
				monitor.set_hostname(host)
				await self.monitor_dispatch_q.put(monitor)
				await monitor.c2d_in.put(c_cmd.to_bytes())
				data = await monitor.c2d_out.get()
			
			else:
				data = c_cmd.to_bytes()
			dst_writer.write(data)
			await dst_writer.drain()

			data = None
			reply, err = await HTTPRequest.from_streamreader(dst_reader, timeout = self.client_timeout)
			if err is not None:
				raise err

			if monitor is not None:
				await monitor.d2c_in.put(reply.to_bytes())
				data = await monitor.d2c_out.get()
			else:
				data = reply.to_bytes()

			writer.write(data)
			await writer.drain()


		except Exception as e:
			srvlogger.exception('[HTTP] Generic error: %s' % (e))

	async def handle_client(self, reader, writer):
		#checking what protocol the client uses
		try:
			try:
				temp = await asyncio.wait_for(reader.readexactly(1), timeout = self.client_timeout)
			except asyncio.exceptions.IncompleteReadError as err:
				srvlogger.debug('Client terminated the socket before socks/http proxy handshake')
				return

			if temp == b'\x04':
				if 'SOCKS4' not in self.supported_protocols:
					raise Exception('Client tried to use SOCKS4, but it is disabled on the server')
				
				temp2 = await asyncio.wait_for(reader.readexactly(7), timeout = self.client_timeout)
				rest = await asyncio.wait_for(reader.readuntil(b'\x00'), timeout = self.client_timeout)
				init_cmd = SOCKS4Request.from_bytes(temp + temp2+ rest)
				await self.handle_socks4(init_cmd, reader, writer)
				return

			elif temp == b'\x05':
				#socks5
				if 'SOCKS5' not in self.supported_protocols:
					raise Exception('Client tried to use SOCKS5, but it is disabled on the server')
				nmethods = await asyncio.wait_for(reader.readexactly(1), timeout = self.client_timeout)
				t_nmethods = int.from_bytes(nmethods, byteorder = 'big', signed = False)
				methods = await asyncio.wait_for(reader.readexactly(t_nmethods), timeout = self.client_timeout)
				init_cmd = SOCKS5Nego.from_bytes(temp + nmethods + methods)
				await self.handle_socks5(init_cmd, reader, writer)
				return

			elif temp in [b'\x43', b'\x63']:
				if 'HTTP' not in self.supported_protocols:
					raise Exception('Client tried to use HTTP proxy, but it is disabled on the server')
				#HTTP CONNECT
				init_cmd, err = await HTTPRequest.from_streamreader(reader, timeout = self.client_timeout, pre_data = temp)
				if err is not None:
					raise err
				await self.handle_http_connect(init_cmd, reader, writer)
				return

			elif temp in [b'g', b'G', b'p', b'P', b'o', b'O']:
				if 'HTTP' not in self.supported_protocols:
					raise Exception('Client tried to use HTTP proxy, but it is disabled on the server')
				init_cmd, err = await HTTPRequest.from_streamreader(reader, timeout = self.client_timeout, pre_data = temp)
				if err is not None:
					raise err

				await self.handle_http_generic(init_cmd, reader, writer)
			else:
				raise Exception('Unknwon protocol used by the client! %s' % temp)


		except Exception as e:
			srvlogger.exception('handle_client')


	
	async def run(self):
		server = await asyncio.start_server(self.handle_client, self.listen_ip, self.listen_port, ssl=self.ssl_ctx)
		await server.wait_closed()
