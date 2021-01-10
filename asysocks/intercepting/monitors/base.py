import asyncio

import logging

from asysocks.common.trafficlog import TrafficLog

srvlogger = logging.getLogger('asysocks.traffic.base')
handler = logging.StreamHandler()
formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
srvlogger.addHandler(handler)
srvlogger.setLevel(logging.INFO)

class BaseMonitor:
	"""
	Base class for monitoring traffic. This does not do monitoring 
	just holds all the necessary data that enables monitoring for 
	other classes
	"""
	def __init__(self, client_ip, client_port, dst_ip, dst_port, module, session_id):
		self.client_ip = client_ip
		self.client_port = client_port
		self.dst_ip = dst_ip
		self.dst_hostname = None
		self.dst_port = dst_port
		self.module = module
		self.session_id = session_id
		self.logline_c2d = '[%s][MONITOR][%s:%s -> %s:%s]' % (self.module, self.client_ip, self.client_port, self.dst_ip, self.dst_port)
		self.logline_d2c = '[%s][MONITOR][%s:%s -> %s:%s]' % (self.module, self.dst_ip, self.dst_port, self.client_ip, self.client_port)

		self.c2d_in = asyncio.Queue()
		self.c2d_out = asyncio.Queue()
		self.d2c_in = asyncio.Queue()
		self.d2c_out = asyncio.Queue()

	def get_trafficlog(self, data, direction, module_name = None):
		t = TrafficLog()
		t.module_name = module_name
		t.srv_module = self.module
		t.client_ip = self.client_ip
		t.client_port = self.client_port
		t.destination_ip = self.dst_ip
		t.destination_hostname = self.dst_hostname
		t.destination_port = self.dst_port
		t.session_id = self.session_id
		t.direction = direction
		t.data = data
		return t

	def get_dst_hostname(self):
		if self.dst_hostname is None:
			return self.dst_ip
		return self.dst_hostname

	def set_hostname(self, hostname):
		#for SNI support on SSL
		self.dst_hostname = hostname
	
	async def __proxy_c2d(self, stop_evt):
		try:
			while not stop_evt.is_set():
				data = await self.c2d_in.get()
				await self.c2d_out.put(data)
				if data == b'':
					return
		except Exception as e:
			srvlogger.exception('__proxy_c2d')
		finally:
			stop_evt.set()

	async def __proxy_d2c(self, stop_evt):
		try:
			while not stop_evt.is_set():
				data = await self.d2c_in.get()
				await self.d2c_out.put(data)
				if data == b'':
					return
		except Exception as e:
			srvlogger.exception('__proxy_d2c')
		finally:
			stop_evt.set()


	async def run(self):
		"""
		Only invoke this if no monitoring is required!
		"""
		stop_evt = asyncio.Event()
		asyncio.create_task(self.__proxy_c2d(stop_evt))
		asyncio.create_task(self.__proxy_d2c(stop_evt))
		await stop_evt.wait()