import ssl
from asysocks.unicomm.common.packetizers import Packetizer

class PacketizerSSL(Packetizer):
	def __init__(self, ssl_ctx, packetizer:Packetizer):
		Packetizer.__init__(self, 16384)
		self.ssl_ctx:ssl.SSLContext = ssl_ctx
		self.packetizer = packetizer
		self.tls_in_buff:ssl.MemoryBIO = None
		self.tls_out_buff:ssl.MemoryBIO = None
		self.tls_obj:ssl.SSLObject = None
		self.__plaintext_buffer = []

	def flush_buffer(self):
		return self.packetizer.flush_buffer()
	
	def set_buffersize(self, buffer_size:int):
		self.packetizer.set_buffersize(buffer_size)
	
	def get_peer_certificate(self):
		return self.tls_obj.getpeercert(binary_form=True)
	
	def packetizer_control(self, *args, **kwargs):
		self.packetizer.packetizer_control(*args, **kwargs)

	async def do_handshake(self, reader, writer, server_side=False):
		#print('do_handshake')
		self.tls_in_buff = ssl.MemoryBIO()
		self.tls_out_buff = ssl.MemoryBIO()
		self.tls_obj = self.ssl_ctx.wrap_bio(self.tls_in_buff, self.tls_out_buff, server_side=server_side) # , server_hostname = self.monitor.dst_hostname

		ctr = 0
		while True:
			ctr += 1
			try:
				self.tls_obj.do_handshake()
			except ssl.SSLWantReadError:
				#print('DST want %s' % ctr)
				while True:
					client_hello = self.tls_out_buff.read()
					if client_hello != b'':
						#print('DST client_hello %s' % len(client_hello))
						writer.write(client_hello)
						await writer.drain()
					else:
						break
				
				#print('DST wating server hello %s' % ctr)
				server_hello = await reader.read(self.buffer_size)
				#print('DST server_hello %s' % len(server_hello))
				self.tls_in_buff.write(server_hello)

				continue
			except:
				raise
			else:
				#print('DST handshake ok %s' % ctr)
				server_fin = self.tls_out_buff.read()
				#print('DST server_fin %s ' %  server_fin)
				if server_fin != b'':
					writer.write(server_fin)
					await writer.drain()
				break
	
	async def data_out(self, data:bytes):
		outdata = b''
		async for packetraw in self.packetizer.data_out(data):
			outdata += packetraw
		self.tls_obj.write(outdata)
		while True:
			raw = self.tls_out_buff.read()
			if raw != b'':
				yield raw
				continue
			break

	async def data_in(self, encdata:bytes):		
		while self.__plaintext_buffer:
			yield self.__plaintext_buffer.pop(0)
			
		if encdata is None:
			yield None
		
		self.tls_in_buff.write(encdata)
		data = b''
		was_data = False
		while True:
			try:
				data += self.tls_obj.read()
				was_data = True
			except ssl.SSLWantReadError:
				break
		if was_data is True:
			async for packet in self.packetizer.data_in(data):
				self.__plaintext_buffer.append(packet)
			
			while self.__plaintext_buffer:
				yield self.__plaintext_buffer.pop(0)