
from typing import List, Tuple, Any, Dict
from asysocks.unicomm.protocol.client.http.commons.messages import MockHTTPRequest, HTTPResponse
from asysocks.unicomm.protocol.client.http.transport import HTTPClientTransport


class RequestManager:
	def __init__(self, session, url:str, req_type:str, headers:List[Tuple[str,str]] = [], data:bytes=None, need_length:bool=False, transport:HTTPClientTransport = None, **kwargs):
		self.session = session
		self.url = url
		self.req_type = req_type
		self.headers = headers
		self.data = data
		self.need_length = need_length
		self.transport = transport
		self.__response = None
	
	async def __aenter__(self) -> HTTPResponse:
		try:
			target, fullurl = self.session.process_url(self.url)
			if self.transport is None:
				self.transport = await self.session.get_transport()
			
			if self.session.authmanager is not None and self.session.authmanager.status == 'start':
				return await self.session.authmanager.authenticate(self)

			else:
				headers = self.session.apply_headers(fullurl, self.headers)
				self.__response = await self.transport.request(fullurl, self.req_type, target, headers=headers, data=self.data, need_length=self.need_length)
				self.session.cookiejar.extract_cookies(self.__response, MockHTTPRequest(fullurl))
				return self.__response
		except Exception as e:
			raise e
	
	async def __aexit__(self, exc_type, exc, tb):
		if self.__response is not None:
			await self.__response.cleanup()