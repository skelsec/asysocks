import asyncio
import traceback
from tqdm import tqdm
import datetime
import sys
from asysocks.unicomm.common.scanner.common import *

class UniScannerExecutor:
	def __init__(self):
		pass

	async def run(self, targetid, target, out_queue):
		await out_queue.put(ScannerData(targetid, 'alma'))

class UniScanner:
	def __init__(self, name, executors, target_generators, worker_count = 100, host_timeout = 5):
		self.name = name
		self.target_generators = target_generators
		self.worker_count = worker_count
		self.host_timeout = host_timeout
		self.__workers = []
		self.__targetgen = None
		self.__targetqueue = None
		self.out_queue = asyncio.Queue()
		self.__total_items = 0
		self.__finished_items = 0
		self.scantime = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
		self.executors = executors
		if isinstance(self.executors, list) is False:
			self.executors = [self.executors]
		if isinstance(self.target_generators, list) is False:
			self.target_generators = [self.target_generators]

	async def worker(self):
		while not asyncio.current_task().cancelled():
			x = await self.__targetqueue.get()
			if x is None:
				return
			targetid, target = x
			for executor in self.executors:
				try:
					await asyncio.wait_for(executor.run(targetid, target, self.out_queue), self.host_timeout)
				except Exception as e:
					await self.out_queue.put(ScannerError(target, e))
			
			self.__finished_items += 1
			await self.out_queue.put(ScannerProgress(self.name, self.__total_items, self.__finished_items))

	async def stop(self):
		for worker in self.__workers:
			worker.cancel()

	async def targets(self):
		for generator in self.target_generators:
			async for targetid, target in generator.run():
				await self.__targetqueue.put((targetid, target))
		for _ in range(len(self.__workers)):
			await self.__targetqueue.put(None)

	async def scan(self):
		try:
			for generator in self.target_generators:
				self.__total_items += generator.get_total()

			
			self.__targetqueue = asyncio.Queue(self.worker_count)
			for _ in range(self.worker_count):
				self.__workers.append(asyncio.create_task(self.worker()))
			self.__targetgen = asyncio.create_task(self.targets())
			yield ScannerStarted(self.name)
			gather_coro = asyncio.gather(*self.__workers)
			while gather_coro.done() is False or self.out_queue.qsize() > 0:
				try:
					result = await asyncio.wait_for(self.out_queue.get(), timeout = 1)
					yield result
				except asyncio.TimeoutError:
					continue
				except:
					break
		except Exception as e:
			yield ScannerError('!SCANNER!', e)
		finally:
			await self.stop()
			yield ScannerFinished(self.name)

	async def scan_and_process(self, progress = True, out_file = None, include_errors = False):
		fhandles = {}
		try:
			def update_pbar(pbar, rtype):
				if len(pbar) == 0:
					return
				if rtype == ScannerResultType.ERROR:
					pbar['errors'].update()
				elif rtype == ScannerResultType.PROGRESS:
					pbar['targets'].update()
				elif rtype == ScannerResultType.FINISHED:
					for k in pbar:
						pbar[k].refresh()
				elif rtype == ScannerResultType.DATA:
					pbar['results'].update()			

			pbar = {}
			if progress is True:
				if out_file is None:
					out_file = os.getcwd()
				for generator in self.target_generators:
					self.__total_items += generator.get_total()

				pbar['targets']    = tqdm(desc='Targets     ', unit='', position=0, total=self.__total_items)
				pbar['results']    = tqdm(desc='Results     ', unit='', position=1)
				pbar['errors']     = tqdm(desc='Errors      ', unit='', position=2)

			async for result in self.scan():
				update_pbar(pbar, result.type)
				if result.type == ScannerResultType.ERROR and include_errors is True:
					if 'error' not in fhandles:
						if out_file is None:
							fhandles['error'] = sys.stderr
						else:
							fhandles['error'] = open(os.path.join(out_file, '%s_error_%s.tsv' % (str(self.name), self.scantime)), 'w', newline = '')
					fhandles['error'].write(result.to_line()+'\r\n')
					
				elif result.type == ScannerResultType.DATA:
					filedata = result.get_fdata()
					if filedata is not None:
						with open(result.get_fname() ,'wb') as f:
							f.write(filedata)
						continue
					if filedata is None:
						rtype = result.get_name()
						if rtype not in fhandles:
							if out_file is None:
								fhandles[rtype] = sys.stdout
							else:
								fhandles[rtype] = open(os.path.join(out_file, '%s_%s%s' %(rtype, self.scantime,'.tsv')), 'w', newline = '')
						fhandles[rtype].write(result.to_line()+'\r\n')

		except Exception as e:
			print('SCANNER CRITICAL ERROR %s' % str(e))
		finally:
			await self.stop()
			for k in fhandles:
				try:
					fhandles[k].close()
				except:
					pass
async def amain():
	try:
		executor = UniScannerExecutor()

		from asysocks.unicomm.common.scanner.targetgen import UniTargetGen
		from aiosmb.commons.connection.factory import SMBConnectionFactory
		connectionfactory = SMBConnectionFactory.from_url('smb2+kerberos-password://TEST.corp\\Administrator:Passw0rd!1@win2019ad.test.corp/')
		scanner = UniScanner('TEST', [executor])
		scanner.target_generators.append(UniTargetGen.from_list(['10.10.10.2', '10.10.10.3']))
		async for x in scanner.scan():
			print(x)
			if x.type == ScannerResultType.ERROR:
				print(x.data)

	except Exception as e:
		traceback.print_exc()

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()
