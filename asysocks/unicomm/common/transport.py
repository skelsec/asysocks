from asyncio.transports import Transport
import asyncio

class UNITransport(Transport):
	"""Base class for WSNET transport."""

	def __init__(self, connection, extra=None):
		Transport.__init__(self)
		self.write_buffer_size = 65535
		self.read_buffer_size = 65535
		self.comms = connection
		self._write_buffer_limits = (0, 0)
		self._protocol = None
		self._isclosing = False

	def get_extra_info(self, name, default=None):
		"""Get optional transport information."""
		print('Extrainfo', name, default)
		return self.comms.get_extra_info(name, default)
		
	def is_closing(self):
		"""Return True if the transport is closing or closed."""
		#print('is_closing')
		return self._isclosing

	def close(self):
		"""Close the transport.
		Buffered data will be flushed asynchronously.  No more data
		will be received.  After all buffered data is flushed, the
		protocol's connection_lost() method will (eventually) be
		called with None as its argument.
		"""
		#print('close')
		self._isclosing = True
		x = asyncio.create_task(self.comms.close())

	def set_protocol(self, protocol):
		"""Set a new protocol."""
		#print('set_protocol', protocol)
		self.comms.protocol = protocol

	def get_protocol(self):
		"""Return the current protocol."""
		return self.comms.protocol

	def is_reading(self):
		#print('is_reading')
		"""Return True if the transport is receiving."""
		return self.comms.read_resume.is_set()

	def pause_reading(self):
		"""Pause the receiving end.
		No data will be passed to the protocol's data_received()
		method until resume_reading() is called.
		"""
		#print('pause_reading')
		x = asyncio.create_task(self.comms.pause_reading())

	def resume_reading(self):
		"""Resume the receiving end.
		Data received will once again be passed to the protocol's
		data_received() method.
		"""
		#print('resume_reading')
		self.comms.read_resume.set()
	
	def set_write_buffer_limits(self, high=None, low=None):
		"""Set the high- and low-water limits for write flow control.
		These two values control when to call the protocol's
		pause_writing() and resume_writing() methods.  If specified,
		the low-water limit must be less than or equal to the
		high-water limit.  Neither value can be negative.
		The defaults are implementation-specific.  If only the
		high-water limit is given, the low-water limit defaults to an
		implementation-specific value less than or equal to the
		high-water limit.  Setting high to zero forces low to zero as
		well, and causes pause_writing() to be called whenever the
		buffer becomes non-empty.  Setting low to zero causes
		resume_writing() to be called only once the buffer is empty.
		Use of zero for either limit is generally sub-optimal as it
		reduces opportunities for doing I/O and computation
		concurrently.
		"""
		#print('set_write_buffer_limits')
		self._write_buffer_limits = (low, high)

	def get_write_buffer_size(self):
		#print('get_write_buffer_size')
		"""Return the current size of the write buffer."""
		return self.write_buffer_size

	def get_write_buffer_limits(self):
		#print('get_write_buffer_limits')
		"""Get the high and low watermarks for write flow control.
		Return a tuple (low, high) where low and high are
		positive number of bytes."""
		return self._write_buffer_limits

	def write(self, data):
		#print('write', data)
		"""Write some data bytes to the transport.
		This does not block; it buffers the data and arranges for it
		to be sent out asynchronously.
		"""
		asyncio.run_coroutine_threadsafe(self.comms.write(data), asyncio.get_event_loop())

	def writelines(self, list_of_data):
		#print('writelines', list_of_data)
		"""Write a list (or any iterable) of data bytes to the transport.
		The default implementation concatenates the arguments and
		calls write() on the result.
		"""
		data = b''.join(list_of_data)
		self.write(data)

	def write_eof(self):
		#print('write_eof')
		"""Close the write end after flushing buffered data.
		(This is like typing ^D into a UNIX program reading from stdin.)
		Data may still be received.
		"""
		self.write(b'')

	def can_write_eof(self):
		#print('can_write_eof')
		"""Return True if this transport supports write_eof(), False if not."""
		return True

	def abort(self):
		#print('abort')
		"""Close the transport immediately.
		Buffered data will be lost.  No more data will be received.
		The protocol's connection_lost() method will (eventually) be
		called with None as its argument.
		"""
		self.close()