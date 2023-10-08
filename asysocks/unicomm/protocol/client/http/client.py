

import re
import copy
import asyncio
import http.cookiejar
from urllib.parse import urlparse, urljoin
from typing import List, Tuple, Any, Dict

from asyauth.common.credentials import UniCredential
from asysocks.unicomm.protocol.client.http.requestmgr import RequestManager
from asysocks.unicomm.protocol.client.http.auth import HTTPAuthManager
from asysocks.unicomm.protocol.client.http.commons.messages import MockHTTPRequest, HTTPResponse
from asysocks.unicomm.protocol.client.http.commons.factory import HTTPConnectionFactory
from asysocks.unicomm.protocol.client.http.transport import HTTPClientTransport
from asysocks.unicomm.common.proxy import UniProxyTarget

http_url_pattern = re.compile(r'^https?:\/\/')

class ClientSession:
	def __init__(self, url:str=None, static_headers:Dict[str, str]={}, credential:UniCredential=None, proxies:List[UniProxyTarget] = None, auth_type='auto', ssl_ctx=None, force_sinle_connection:bool=False):
		self.url = url
		self.cookiejar:http.cookiejar.CookieJar = http.cookiejar.CookieJar()
		self.factory:HTTPConnectionFactory = None
		self.authmanager:HTTPAuthManager = None
		self.ssl_ctx = ssl_ctx
		self.static_headers = static_headers
		self.force_sinle_connection = force_sinle_connection
		self.auth_type = auth_type
		self.proxies = proxies
		if self.url is not None:
			self.factory = HTTPConnectionFactory.from_url(url, self.proxies)
		if credential is not None:
			self.authmanager = HTTPAuthManager.from_credential(self, credential, auth_type=self.auth_type)
		self.connections = []
		self.session_closed_evt = asyncio.Event()
	
	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc, tb):
		await self.close()
	
	async def close(self):
		if self.session_closed_evt.is_set() is True:
			return
		self.session_closed_evt.set()
		for conn in self.connections:
			await conn.disconnect()
		self.connections = []
	
	def process_url(self, url:str):
		if bool(http_url_pattern.match(url)) is True:
			parsed_url = urlparse(url)
			#if self.url is not None:
			#	temp = f"{parsed_url.scheme}://{parsed_url.netloc}/"
			#	if temp != self.url:
			#		raise Exception('URL was already specified!')
			
			self.url = url
			self.factory = HTTPConnectionFactory.from_url(url, self.proxies)
			if self.factory.get_credential() is not None:
				self.authmanager = HTTPAuthManager.from_credential(self, self.factory.get_credential(), self.auth_type)

			target = parsed_url.path
			if target == '':
				target = '/'
			if target.startswith('/') is False:
				target = '/' + target
			if parsed_url.query != '':
				target += parsed_url.query
		
		else:
			target = url
			if target == '':
				target = '/'
			if target.startswith('/') is False:
				target = '/' + target
			
		original_url = urljoin(self.url, target)
		return target, original_url
	
	async def get_transport(self) -> HTTPClientTransport:
		if self.factory is None:
			raise Exception('No URL was specified!')
		if self.force_sinle_connection is True and len(self.connections) > 0:
			return self.connections[0]
		conn = HTTPClientTransport(self.factory.get_target())
		await conn.connect()
		self.connections.append(conn)
		return conn
	
	def apply_cookies(self, url:str, headers:List[Tuple[str,str]]) -> List[Tuple[str,str]]:
		req = MockHTTPRequest(url)
		self.cookiejar.add_cookie_header(req)
		for entry in req._headers:
			headers.append((entry, req._headers[entry]))
		return headers
	
	def apply_headers(self, url, headers:List[Tuple[str,str]]) -> List[Tuple[str,str]]:
		final_headers = copy.deepcopy(headers)
		entry_exists = lambda entry, lst: any(x[0] == entry for x in lst)
		
		for entry in self.static_headers:
			if not entry_exists(entry, final_headers):
				final_headers.append((entry, self.static_headers[entry]))
		self.apply_cookies(url, final_headers)
		return final_headers

	def get(self, url: str, *, allow_redirects: bool = True, headers=[], **kwargs: Any) -> RequestManager:
		return RequestManager(self, url, 'GET', allow_redirects=allow_redirects, headers=headers, **kwargs)

	def post(self, url: str, *, data: bytes = None, allow_redirects: bool = True, headers=[], **kwargs: Any) -> RequestManager:
		return RequestManager(self, url, 'POST', data=data, allow_redirects=allow_redirects, headers=headers, need_length=True, **kwargs)
	

async def amain():
	#target = UniTarget('www.google.com', 443, protocol=UniProto.CLIENT_SSL_TCP)
	#conn = HTTPClientTransport(target)
	#await conn.connect()
	#resp = await conn.get(headers=[('Connection', 'keep-alive')])
	#print(resp.headers)
	#await asyncio.sleep(10)
	#x = await resp.text()
	#await asyncio.sleep(100)

	async with ClientSession() as session:
		async with session.get('http://www.google.com/') as resp:
			print(resp.status)
			print(await resp.text())
		async with session.get('http://www.google.com/') as resp:
			print(resp.status)
			#print(await resp.text())


	#async with ClientSession() as session:
	#	resp = await session.get('http://www.google.com/')
	#	print(resp.status)
	#	print(await resp.text())

	#session = ClientSession('http://www.google.com/')
	#resp = await session.get('/')
	#print(resp.headers)
	##print(await resp.text())
	#print()
	#print(session.cookiejar)
	#resp = await session.get('/')
	#print(resp.headers)
	##print(await resp.text())

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()



	
