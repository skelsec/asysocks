
# https://www.openssh.com/txt/socks4a.protocol

import io
import os
import enum
import ipaddress
import socket
import asyncio

SOCKS4_USERID_MAC_LEN = 255

class SOCKS4ACDCode(enum.Enum):
	REQ_CONNECT = 1
	REQ_BIND = 2

	REP_GRANTED = 90 #request granted
	REP_FAILED = 91 #request rejected or failed
	REP_FAILED_NOCONN = 92 #request rejected becasue SOCKS server cannot connect to identd on the client
	REP_FAILED_USRID_MISMATCH = 93 #request rejected because the client program and identd report different user-ids

class SOCKS4ARequest:
	def __init__(self):
		self.VN = 4
		self.CD = SOCKS4ACDCode.REQ_CONNECT
		self.DSTPORT = None
		self.DSTIP = None
		self.USERID = None
		self.DOMAIN = None
	
	@staticmethod
	def from_bytes(data):
		return SOCKS4ARequest.from_buffer(io.BytesIO(data))

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		try:
			buff = b''
			t = await asyncio.wait_for(reader.readexactly(4), timeout = timeout)
			buff += t
			t = await asyncio.wait_for(reader.readexactly(4), timeout = timeout)
			buff += t
			r = 1
			if t[0:3] == b'\x00\x00\x00':
				r = 2
			
			for _ in range(0,r):
				t = await asyncio.wait_for(reader.readuntil(b'\x00'), timeout = timeout)
				buff += t
			return SOCKS4ARequest.from_bytes(buff), None
		except Exception as e:
			return None, e

	@staticmethod
	def from_buffer(buff):
		o = SOCKS4ARequest()
		o.VN = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		o.CD = SOCKS4ACDCode(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		o.DSTPORT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		o.DSTIP = ipaddress.IPv4Address(buff.read(4))
		o.USERID = b''
		for _ in range(SOCKS4_USERID_MAC_LEN):
			x = buff.read(1)
			if x == 0:
				break
			o.USERID += x
		
		if str(o.DSTIP).startswith('0.0.0.'):
			for _ in range(SOCKS4_USERID_MAC_LEN):
				x = buff.read(1)
				if x == 0:
					break
				o.DOMAIN += x
		return o

	@staticmethod
	def from_target(target):
		o = SOCKS4ARequest()
		if target.is_bind is True:
			SOCKS4ACDCode.REQ_BIND
		o.DSTPORT = target.endpoint_port
		if isinstance(target.endpoint_ip, ipaddress.IPv4Address):
			o.DSTIP = target.endpoint_ip
		else:
			try:
				o.DSTIP = ipaddress.ip_address(target.endpoint_ip)
			except:
				o.DSTIP = ipaddress.ip_address('0.0.0.3')
				o.DOMAIN = str(target.endpoint_ip)
		o.USERID = target.userid
		if target.userid is None:
			o.USERID = os.urandom(4).hex().encode('ascii')

		return o

	def to_bytes(self):
		t = self.VN.to_bytes(1, byteorder = 'big', signed = False)
		t += self.CD.value.to_bytes(1, byteorder = 'big', signed = False)
		t += self.DSTPORT.to_bytes(2, byteorder = 'big', signed = False)
		t += self.DSTIP.packed
		t += self.USERID
		t += b'\x00' #trailing for userid
		if self.DOMAIN is not None:
			t += self.DOMAIN.encode()
			t += b'\x00'
		return t

class SOCKS4AReply:
	def __init__(self):
		self.VN = 0
		self.CD = None
		self.DSTPORT = None
		self.DSTIP = None

	@staticmethod
	def from_bytes(data):
		return SOCKS4AReply.from_buffer(io.BytesIO(data))

	@staticmethod
	async def from_streamreader(reader, timeout = None):
		try:
			t = await asyncio.wait_for(reader.readexactly(8), timeout = timeout)
			return SOCKS4AReply.from_bytes(t), None
		except Exception as e:
			return None, e

	@staticmethod
	def from_buffer(buff):
		o = SOCKS4AReply()
		o.VN = int.from_bytes(buff.read(1), byteorder = 'big', signed = False)
		o.CD = SOCKS4ACDCode(int.from_bytes(buff.read(1), byteorder = 'big', signed = False))
		o.DSTPORT = int.from_bytes(buff.read(2), byteorder = 'big', signed = False)
		o.DSTIP = ipaddress.IPv4Address(buff.read(4))
		return o

	def to_bytes(self):
		t = self.VN.to_bytes(1, byteorder = 'big', signed = False)
		t += self.CD.value.to_bytes(1, byteorder = 'big', signed = False)
		t += self.DSTPORT.to_bytes(2, byteorder = 'big', signed = False)
		t += self.DSTIP.packed
		return t
