import enum
import os
import datetime
import traceback

class ScannerResultType(enum.Enum):
	STARTED = 'STARTED'
	ERROR = 'ERROR'
	DATA = 'DATA'
	PROGRESS = 'PROGRESS'
	FINISHED = 'FINISHED'
	INFO = 'INFO'

class ScannerResult:
	def __init__(self, type, resid, data = None):
		self.type = type
		self.resid = str(resid)
		self.data = data

	def to_line(self, separator = '\t'):
		raise NotImplementedError()

class ScannerStarted(ScannerResult):
	def __init__(self, scannername):
		ScannerResult.__init__(
			self,
			ScannerResultType.STARTED,
			scannername
		)
	def to_line(self, separator = '\t'):
		return separator.join(['STARTED', '%s' % self.type])

class ScannerFinished(ScannerResult):
	def __init__(self, scannername):
		ScannerResult.__init__(
			self,
			ScannerResultType.FINISHED,
			scannername
		)
	def to_line(self, separator = '\t'):
		return separator.join(['FINISHED','%s' % self.type])

class ScannerError(ScannerResult):
	def __init__(self, resid, error):
		ScannerResult.__init__(
			self, 
			ScannerResultType.ERROR,
			resid,
			error
		)
		self.traceback = None
		if isinstance(error, Exception) is True:
			self.traceback = error.__traceback__
			self.data = repr(error)
	
	def to_line(self, separator = '\t'):
		return separator.join(['ERROR', str(self.resid), str(self.data)]) #.replace('\r','').replace('\n', '').replace('\t', ' ')

	def to_traceback(self):
		if self.traceback is not None:
			return ''.join(traceback.format_tb(self.traceback))

class ScannerData(ScannerResult):
	def __init__(self, resid, data):
		ScannerResult.__init__(
			self,
			ScannerResultType.DATA,
			resid,
			data
		)

	def get_name(self):
		try:
			return self.data.get_name()
		except:
			return str(type(self.data).__name__)

	def get_fname(self):
		try:
			return self.data.get_fname()
		except:
			return 'scandata_%s_%s.bin' % (os.urandom(4).hex(), datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
	
	def get_fdata(self):
		try:
			return self.data.get_fdata()
		except:
			return None

	def __flatten_data(self):
		try:
			return self.data.to_line()
		except:
			return str(self.data)

	def to_line(self, separator = '\t'):
		res = ''
		for line in self.__flatten_data().split('\n'):
			line = line.strip()
			res += separator.join([str(self.resid), line])#  + '\r\n'

		return res

class ScannerProgress(ScannerResult):
	def __init__(self, scannername, total, current):
		ScannerResult.__init__(
			self,
			ScannerResultType.PROGRESS,
			scannername
		)
		self.total = total
		self.current = current
	
	def to_percent(self):
		if self.total is None or self.total == 0:
			return 'x'
		return (self.current/self.total)*100

	def to_line(self, separator = '\t'):
		return separator.join(['PROGRESS', '%s\\%s (%s%%)' % (self.total, self.current, self.to_percent())])

class ScannerInfo(ScannerResult):
	def __init__(self, resid, info):
		ScannerResult.__init__(
			self,
			ScannerResultType.INFO,
			resid,
			info
		)
	
	def to_line(self, separator = '\t'):
		res = ''
		for line in str(self.data).split('\n'):
			line = line.strip()
			res += separator.join(['INFO', str(self.resid), line]) + '\r\n'

		return res