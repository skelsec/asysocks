import h11
import asyncio
import traceback
from typing import List, Tuple, Any, Union, Dict
from asysocks.unicomm.client import UniClient
from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.common.packetizers import Packetizer
from asysocks.unicomm.protocol.client.http.commons.messages import HTTPResponse
from asysocks.unicomm.protocol.client.http.commons.target import HTTPTarget


class HTTPClientTransport:
	def __init__(self, target:HTTPTarget, request_connection_type='keep-alive'):
		self.target = target
		self.connection_closed_evt = None
		self.connection = None
		self.httpconn = None
		self.request_connection_type = request_connection_type
		self.response_connection_type = request_connection_type
		self.__disconnect_requested = False

	async def __next_event(self):
		try:
			while self.connection_closed_evt.is_set() is False:
				event = self.httpconn.next_event()
				if event is h11.NEED_DATA:
					data = await self.connection.read_one()
					self.httpconn.receive_data(data)
				if event is h11.ConnectionClosed:
					await self.disconnect()
					break
				yield event
			await self.disconnect_if_needed()
			#if self.__disconnect_requested is True:
			#	await self.disconnect_if_needed()
		except Exception as e:
			await self.disconnect()
			traceback.print_exc()
			
	
	async def __send(self, event):
		data = self.httpconn.send(event)
		if type(data) is h11.ConnectionClosed:
			self.__disconnect_requested = True
			return
		if data == b'':
			# the client requests the connection to be closed, but we must wait for the server to send the response
			# this is done correctly in asyncio but the proxies are not asyncio friendly
			return
		#print('write: %s' % data)
		await self.connection.write(data)
	
	@property
	def supports_keepalive(self):
		return self.response_connection_type == self.request_connection_type == 'keep-alive'
	
	@property
	def can_reuse(self):
		return self.supports_keepalive is True and self.connection_closed_evt.is_set() is False

	async def connect(self):
		self.httpconn = h11.Connection(our_role=h11.CLIENT)
		self.connection_closed_evt = asyncio.Event()
		packetizer = Packetizer()
		client = UniClient(self.target, packetizer)
		self.connection = await client.connect()
	
	async def disconnect_if_needed(self):
		if self.can_reuse is False:
			await self.disconnect()
	
	async def disconnect(self):
		self.__disconnect_requested = True
		self.connection_closed_evt.set()
		if self.connection is not None:
			await self.connection.close()
		
	
	def __correct_headers(self, headers:List[Tuple[str,str]], data:bytes=b'', need_length:bool=False):
		has_host = False
		has_connection = False
		has_length = False
		for entry in headers:
			if entry[0].lower() == 'host':
				has_host = True
			elif entry[0].lower() == 'connection':
				has_connection = True
				self.request_connection_type = entry[1].lower()
			elif entry[0].lower() == 'content-length':
				has_length = True
		if has_host is False:
			headers.append(('Host', self.target.get_hostname_or_ip()))
		if has_connection is False:
			headers.append(("Connection", self.request_connection_type))
		if need_length is True and has_length is False:
			if data is None:
				data = b''
			headers.append(("Content-Length", str(len(data))))
		return headers
	
	async def __read_header(self, fullurl):
		async for event in self.__next_event():
			if type(event) is h11.Response:
				return HTTPResponse.from_h11_header(event, self.__next_event, self, fullurl)
			if type(event) is h11.EndOfMessage:
				raise Exception('Response ended without server sending headers!')
			if type(event) is h11.ConnectionClosed:
				raise Exception('Server terminated the connection!')

	async def request(self, fullurl, req_type:str, target:str = '/', headers:List[Tuple[str,str]] = [], data:bytes=None, need_length:bool=False):
		if self.httpconn.states[h11.CLIENT] == self.httpconn.states[h11.SERVER] == h11.DONE:
			self.httpconn.start_next_cycle()
		request_header = self.__correct_headers(headers, data, need_length)
		request_event = h11.Request(
			method=req_type,
			target=target,
			headers=request_header,
		)
			
		await self.__send(request_event)
		if data is not None:
			if type(data) is str:
				data = data.encode()
			await self.__send(h11.Data(data=data))
		await self.__send(h11.EndOfMessage())

		response = await self.__read_header(fullurl)
		
		for header in response.headers:
			if header.lower() == 'connection':
				self.response_connection_type = response.headers[header][0].lower()
		return response