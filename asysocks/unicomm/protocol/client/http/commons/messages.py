import h11
import json
import codecs
from typing import List, Tuple, Any, Union, Dict


def is_supported_encoding(enc):
    try:
        codecs.lookup(enc)
        return True
    except LookupError:
        return False

class MockHTTPRequest:
	"""Do NOT use this class directly! It is only used to make the code compatible with python's cookiejar"""
	def __init__(self, url):
		self._url = url
		self._headers = {}

	def get_header(self, name, default=None):
		return self._headers.get(name, default)
	
	def get_type(self):
		return self._url.split(':')[0]

	def get_host(self):
		return self._url.split('/')[2]

	def get_full_url(self):
		return self._url

	def get_origin_req_host(self, origin=False):
		return self.get_host()

	@property
	def unverifiable(self):
		return False
	
	@property
	def type(self):
		return self.get_type()
	
	def has_header(self, name):
		return self.get_header(name, False)
	
	def add_unredirected_header(self, name, value):
		self._headers[name] = value

class HTTPResponse:
	def __init__(self):
		self.status:int = None
		self.http_version:str = None
		self.reason:str = None
		self.headers:Dict[str, List[str]] = {}
		self.h11:h11.Response = None
		self.data_iter = None
		self.transport = None
		self.url = None
		self.__all_data_consumed = False
	
	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc, tb):
		await self.cleanup()
	
	async def cleanup(self):
		if self.data_iter is not None and self.__all_data_consumed is False:
			async for event in self.data_iter():
				if type(event) is h11.EndOfMessage:
					break
				if type(event) is h11.ConnectionClosed:
					break
				continue
		if self.transport is not None:
			await self.transport.disconnect_if_needed()
	
	@staticmethod
	def from_h11_header(rh:h11.Response, data_iter, transport, fullurl):
		resp = HTTPResponse()
		resp.url = fullurl
		resp.h11 = rh
		resp.status = rh.status_code
		resp.http_version = rh.http_version.decode()
		resp.reason = rh.reason.decode()
		resp.headers = {}
		resp.transport = transport
		for entry in rh.headers:
			name = entry[0].decode()
			value = entry[1].decode()
			if name == 'set-cookie':
				name = 'Set-Cookie'
			if name not in resp.headers:
				resp.headers[name] = []
			resp.headers[name].append(value)
		resp.data_iter = data_iter
		return resp
	
	def info(self):
		return self

	def getheaders(self, name):
		return self.headers.get(name)

	def get_all(self, name, default):
		return self.headers.get(name, default)
	
	async def stream_data(self):
		async for event in self.data_iter():
			if type(event) is h11.Data:
				yield event.data
			if type(event) is h11.EndOfMessage:
				self.__all_data_consumed = True
				break
	
	async def read(self):
		data = b''
		async for chunk in self.stream_data():
			data += chunk
		return data
	
	async def text(self):
		codec = 'utf-8'
		if 'content-type' in self.headers:
			for entry in self.headers['content-type']:
				if 'charset=' in entry:
					codec = entry.split('charset=')[1]
					break
		if is_supported_encoding(codec) is False:
			codec = 'utf-8'
		data = b''
		async for chunk in self.stream_data():
			data += chunk
		return data.decode(codec)
	
	async def json(self):
		return json.loads(await self.text())
	
	def __str__(self):
		t = 'HTTPResponse\r\n'
		t += 'HTTP/%s %s %s\r\n' % (self.http_version, self.status, self.reason)
		for k in self.headers:
			if isinstance(self.headers[k], list):
				for v in self.headers[k]:
					t += '%s: %s\r\n' % (k, v)
			else:
				t += '%s: %s\r\n' % (k, self.headers[k])
		return t