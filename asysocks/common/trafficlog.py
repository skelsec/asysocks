

class TrafficLog:
	def __init__(self):
		self.client_ip = None
		self.client_port = None
		self.destination_ip = None
		self.destination_hostname = None
		self.destination_port = None
		self.session_id = None
		self.direction = None
		self.module = None
		self.srv_module = None
		self.is_ssl = False
		self.data = None

	def get_dst_hostname(self):
		if self.destination_hostname is None:
			return self.destination_ip
		return self.destination_hostname

	def get_header(self):
		return '[%s][%s][%s][%s:%s %s %s:%s] ' % (
			self.srv_module, 
			self.module,
			self.session_id,
			self.client_ip, 
			self.client_port, 
			'->' if self.direction.startswith('c2d') else '<-',
			self.get_dst_hostname(),
			self.destination_port
		)

	def __str__(self):
		return self.get_header() + str(self.data)