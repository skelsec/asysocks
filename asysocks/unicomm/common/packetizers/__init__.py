class Packetizer:
	def __init__(self, buffer_size = 65535):
		self.buffer_size = buffer_size
	
	def packetizer_control(self, *args, **kw):
		return None
	
	def flush_buffer(self):
		return b''

	def set_buffersize(self, buffer_size:int):
		self.buffer_size = buffer_size
	
	async def data_out(self, data):
		yield data

	async def data_in(self, data):
		yield data