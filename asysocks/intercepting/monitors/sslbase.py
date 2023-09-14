import asyncio
import ssl
import logging

srvlogger = logging.getLogger('asysocks.traffic.ssl')
handler = logging.StreamHandler()
formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
srvlogger.addHandler(handler)
srvlogger.setLevel(logging.INFO)


class SSLBaseMonitor:
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

		self.c2d_in = asyncio.Queue()
		self.c2d_out = asyncio.Queue()
		self.d2c_in = asyncio.Queue()
		self.d2c_out = asyncio.Queue()

	def get_trafficlog(self, data, direction, module_name = None):
		t = self.monitor.get_trafficlog(data, direction, module_name = module_name)
		t.is_ssl = True
		return t

	async def __read_ssl_record(self, raw_in_q, ssl_in_q):
		try:
			buffer = b''
			length = None
			while not self.stop_evt.is_set():
				
				if length is None and len(buffer) >= 6:
					length = int.from_bytes(buffer[3:5], byteorder = 'big', signed = False)
				
				if length is not None and len(buffer) >= length + 5:
					#print('LB raw %s' % len(buffer[:length+5]))
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
			#print('################## %s' % self.monitor.dst_ip)

			ctr = 0
			while not self.stop_evt.is_set():
				ctr += 1
				#print('DST Performing handshake!')
				try:
					tls_obj.do_handshake()
				except ssl.SSLWantReadError:
					#print('DST want %s' % ctr)
					while True:
						client_hello = tls_out_buff.read()
						if client_hello != b'':
							#print('DST client_hello %s' % len(client_hello))
							await out_q.put(client_hello)
						else:
							break
					
					#print('DST wating server hello %s' % ctr)
					server_hello = await in_q.get()
					#print('DST server_hello %s' % len(server_hello))
					tls_in_buff.write(server_hello)

					continue
				except:
					raise
				else:
					#print('DST handshake ok %s' % ctr)
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

	async def __read_dec(self, ssl_in_q, final_out_q, tls_in, tls_obj):
		try:
			while True:
				ssl_data = await ssl_in_q.get()
				if ssl_data == b'':
					await final_out_q.put(ssl_data)
					#print('Connection terminated')
					return
				tls_in.write(ssl_data)

				data_buff = b''
				while True:
					try:
						data_buff += tls_obj.read()
					except ssl.SSLWantReadError:
						break
				#print('data_buff %s' % data_buff)
				if data_buff != b'':
					await final_out_q.put(data_buff)

		except Exception as e:
			print(e)

	async def __client_ssl_endpoint(self):
		try:
			self.client_tls_in_buff, self.client_tls_out_buff, self.client_tls_obj, err = await self.__do_ssl_handshake_srv(self.client_ssl_ctx, self.__client_ssl_in_q, self.monitor.d2c_out)
			if err is not None:
				raise err
			print('CLIENT Handshake OK!')
			self.client_ssl_ok_evt.set()
			await self.destination_ssl_ok_evt.wait()
			asyncio.create_task(self.__read_dec(self.__client_ssl_in_q, self.c2d_in, self.client_tls_in_buff, self.client_tls_obj))
			while not self.stop_evt.is_set():
				client_data_buff = await self.c2d_out.get()
				if client_data_buff == b'':
					await self.monitor.c2d_out.put(client_data_buff)
					break
				#print('client_data %s' % client_data_buff)
				self.destination_tls_obj.write(client_data_buff)
				while True:
					client_ssl_data = self.destination_tls_out_buff.read()
					if client_ssl_data == b'':
						break
					#print('client_ssl_data %s' % client_ssl_data)
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
			asyncio.create_task(self.__read_dec(self.__destination_ssl_in_q, self.d2c_in, self.destination_tls_in_buff, self.destination_tls_obj))
			while not self.stop_evt.is_set():
				destination_data_buff = await self.d2c_out.get()
				if destination_data_buff == b'':
					await self.monitor.d2c_out.put(destination_data_buff)
					break
				print('destination_data %s' % destination_data_buff)
				self.client_tls_obj.write(destination_data_buff)
					
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


	
	async def run(self):
		self.c2d_ssl_task = asyncio.create_task(self.__read_ssl_record(self.monitor.c2d_in, self.__client_ssl_in_q))
		self.d2c_ssl_task = asyncio.create_task(self.__read_ssl_record(self.monitor.d2c_in, self.__destination_ssl_in_q))
		self.dest_task = asyncio.create_task(self.__destination_ssl_endpoint())
		self.client_task = asyncio.create_task(self.__client_ssl_endpoint())
		await self.stop_evt.wait()