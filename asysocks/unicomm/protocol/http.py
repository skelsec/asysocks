import asyncio
import io

class HTTPProxyAuthRequiredException(Exception):
	pass

class HTTPProxyAuthFailed(Exception):
	pass

class HTTPResponse:
	def __init__(self):
		self.version = None
		self.status = None
		self.reason = None
		self.headers = {}
		self.headers_upper = {}
		self.data = None

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		try:
			resp = HTTPResponse()
						
			#reading headers
			temp = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), timeout = timeout)
			temp = temp.split(b'\r\n')[:-1]
			version, status, reason = temp[0].split(b' ', 2)
			resp.version = version.decode()
			resp.status = int(status.decode())
			resp.reason = reason.decode()

			for hdr_raw in temp[1:]:
				if hdr_raw.strip() == b'':
					continue
				key_raw, value_raw = hdr_raw.split(b': ', 1)
				key = key_raw.decode()
				value = value_raw.strip().decode()

				resp.headers[key] = value
				resp.headers_upper[key.upper()] = value
						
			if 'CONTENT-LENGTH' in resp.headers_upper:
				rem_len = int(resp.headers_upper['CONTENT-LENGTH'])
				resp.data = await asyncio.wait_for(reader.readexactly(rem_len), timeout = timeout)

			return resp, None
		
		except Exception as e:
			return None, e

class HTTPRequest:
	def __init__(self):
		self.method = None
		self.uri = None
		self.version = None
		self.headers = {}
		self.headers_upper = {}
		self.data = None

	def __str__(self):
		t = '%s %s %s\r\n' % (self.method, self.uri, self.version)
		for x in self.headers:
			t += '%s: %s\r\n' % (x, self.headers[x])
		t += '\r\n'
		if self.data is not None:
			t += '<DATA AVAILABLE>'
		return t

	def to_bytes(self):
		t = '%s %s %s\r\n' % (self.method, self.uri, self.version)
		for x in self.headers:
			t += '%s: %s\r\n' % (x, self.headers[x])
		t += '\r\n'
		t = t.encode()
		if self.data is not None:
			t += self.data
		return t

	@staticmethod
	async def from_streamreader(reader, timeout = None, pre_data = None):
		try:
			req = HTTPRequest()

			#reading headers
			temp = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), timeout = timeout)
			if pre_data is not None:
				temp = pre_data + temp
			temp = temp.split(b'\r\n')[:-1]
			method, uri, version = temp[0].split(b' ', 2)
			req.method = method.decode()
			req.uri = uri.decode()
			req.version = version.decode()
			

			for hdr_raw in temp[1:]:
				if hdr_raw.strip() == b'':
					continue
				key_raw, value_raw = hdr_raw.split(b': ', 1)
				key = key_raw.decode()
				value = value_raw.strip().decode()

				req.headers[key] = value
				req.headers_upper[key.upper()] = value
						
			if 'CONTENT-LENGTH' in req.headers_upper:
				rem_len = int(req.headers_upper['CONTENT-LENGTH'])
				req.data = await asyncio.wait_for(reader.readexactly(rem_len), timeout = timeout)

			return req, None
		
		except Exception as e:
			return None, e