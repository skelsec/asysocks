
import asyncio
import logging
import json
import re
import ssl



from asysocks.intercepting.monitors import prototable
from asysocks.intercepting.monitors.sslbase import SSLBaseMonitor
from asysocks.intercepting.default_intercept_table import default_intercept_table

logger = logging.getLogger('asysocks.intercept')
handler = logging.StreamHandler()
formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class InterceptServer:
	def __init__(self, server, certmanager, log_queue, intercept_targets = None, protocol_load_table = None):
		self.server = server
		self.certmanager = certmanager
		self.log_queue = log_queue
		self.intercept_targets = intercept_targets
		self.protocol_load_table = protocol_load_table
		self.monitor_dispatch_q = asyncio.Queue()

		self.server_task = None
		self.processing_task = None

		self.setup()

	def setup(self):
		if self.protocol_load_table is None:
			self.protocol_load_table = prototable
		
		if self.intercept_targets is None:
			self.intercept_targets = default_intercept_table

	async def __lookup_monitor(self, monitor):
		try:
			selected_protocol = monitor
			for entry in self.intercept_targets:
				is_ssl, proto = entry.get_proto_for_monitor(monitor)
				if proto is not None:
					if is_ssl is True:
						
						client_ssl_ctx = ssl.create_default_context()
						client_ssl_ctx.check_hostname = False
						client_ssl_ctx.verify_mode = ssl.CERT_NONE
						
						fake_cert_file, fake_key_file, err = await self.certmanager.get_cert_by_host(monitor.get_dst_hostname(), port = monitor.dst_port)
						if err is not None:
							print(err)
							return monitor, err

						client_ssl_ctx.load_cert_chain(fake_cert_file, fake_key_file)
						
						destination_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
						destination_ssl_ctx.check_hostname = False
						destination_ssl_ctx.verify_mode = ssl.CERT_NONE

						monitor = SSLBaseMonitor(monitor, client_ssl_ctx = client_ssl_ctx, destination_ssl_ctx = destination_ssl_ctx)
						asyncio.create_task(monitor.run())
					
					selected_protocol = self.protocol_load_table[proto](monitor, self.log_queue)
					break			
			
			return selected_protocol, None
		except Exception as e:
			return None, e

	async def __process_monitors(self):
		try:
			print(2)
			while True:
				#each connection will give a monitor class
				monitor = await self.monitor_dispatch_q.get()
				print('monitor_in')
				monitor_protocol, err = await self.__lookup_monitor(monitor)
				if err is not None:
					print(err)
					raise err
				print(44)
				asyncio.create_task(monitor_protocol.run())

		except Exception as e:
			logger.exception('__process_monitors')
			print(e)


	async def run(self):
		self.server.monitor_dispatch_q = self.monitor_dispatch_q
		self.server_task = asyncio.create_task(self.server.run())
		await asyncio.sleep(0)
		await self.__process_monitors()