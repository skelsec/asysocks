import asyncio
import logging

srvlogger = logging.getLogger('asysocks.traffic.raw')
handler = logging.StreamHandler()
formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
srvlogger.addHandler(handler)
srvlogger.setLevel(logging.INFO)

class RawLoggingMonitor:
	"""
	Logs raw socket data, no SSL intercpetion or protocol reconstruction done
	"""
	def __init__(self, monitor, log_queue, c2d_in = None, c2d_out = None, d2c_in = None, d2c_out = None):
		self.monitor = monitor
		self.log_queue = log_queue
		self.module_name = 'RAWLOG'

	async def __justlog_c2d(self, stop_evt):
		try:
			while not stop_evt.is_set():
				data = await self.monitor.c2d_in.get()
				await self.log_queue.put(self.monitor.get_trafficlog(data, 'c2d_in', self.module_name))
				await self.monitor.c2d_out.put(data)
				if data == b'':
					return
		except Exception as e:
			srvlogger.exception('__justlog_c2d')
		finally:
			stop_evt.set()

	async def __justlog_d2c(self, stop_evt):
		try:
			while not stop_evt.is_set():
				data = await self.monitor.d2c_in.get()
				await self.log_queue.put(self.monitor.get_trafficlog(data, 'd2c_in', self.module_name))
				await self.monitor.d2c_out.put(data)
				if data == b'':
					return
		except Exception as e:
			srvlogger.exception('__justlog_d2c')
		finally:
			stop_evt.set()

	async def run(self):
		stop_evt = asyncio.Event()
		asyncio.create_task(self.__justlog_c2d(stop_evt))
		asyncio.create_task(self.__justlog_d2c(stop_evt))
		await stop_evt.wait()
