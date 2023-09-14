import os
import ssl
import enum
from typing import List
from urllib.parse import urlparse, parse_qs
import copy

def stru(x):
	return str(x).upper()

class UniProxyProto(enum.Enum):
	CLIENT_SOCKS4 = 1
	CLIENT_SSL_SOCKS4 = 2
	CLIENT_SOCKS5_TCP = 3
	CLIENT_SOCKS5_UDP = 4
	CLIENT_SSL_SOCKS5_TCP = 5
	CLIENT_SSL_SOCKS5_UDP = 6
	CLIENT_HTTP = 7
	CLIENT_SSL_HTTP = 8
	CLIENT_WSNET = 9
	CLIENT_CUSTOM = 998
	CLIENT_WSNETTEST = 999
	CLIENT_WSNETDIRECT = 17
	CLIENT_SSL_WSNETDIRECT = 18
	CLIENT_WSNETWS = 10
	CLIENT_SSL_WSNETWS = 11
	SERVER_WSNET = 12
	SERVER_SOCKS5_TCP = 13
	SERVER_SOCKS5_UDP = 14
	SERVER_SSL_SOCKS5_TCP = 15
	SERVER_SSL_SOCKS5_UDP = 16

proxyshort_to_type = {
	'SOCKS4' : UniProxyProto.CLIENT_SOCKS4,
	'SOCKS4S' : UniProxyProto.CLIENT_SSL_SOCKS4,
	'SOCKS5' : UniProxyProto.CLIENT_SOCKS5_TCP,
	'SOCKS5U' : UniProxyProto.CLIENT_SOCKS5_UDP,
	'SOCKS5S' : UniProxyProto.CLIENT_SSL_SOCKS5_TCP,
	'HTTP' : UniProxyProto.CLIENT_HTTP,
	'HTTPS' : UniProxyProto.CLIENT_SSL_HTTP,
	'WSNET' : UniProxyProto.CLIENT_WSNET,
	'WSNETTEST' : UniProxyProto.CLIENT_WSNETTEST,
	'WSNETWS' : UniProxyProto.CLIENT_WSNETWS,
	'WSNETWSS' : UniProxyProto.CLIENT_SSL_WSNETWS,
	'WSNETDIRECT': UniProxyProto.CLIENT_WSNETDIRECT,
	'WSNETDIRECTSSL': UniProxyProto.CLIENT_SSL_WSNETDIRECT,
	'CUSTOM': UniProxyProto.CLIENT_CUSTOM,
}

proxyshort_protocol_defport = {
	UniProxyProto.CLIENT_SOCKS4 : 1080,
	UniProxyProto.CLIENT_SSL_SOCKS4 : 1080,
	UniProxyProto.CLIENT_SOCKS5_TCP: 1080,
	UniProxyProto.CLIENT_SOCKS5_UDP: 1080,
	UniProxyProto.CLIENT_SSL_SOCKS5_TCP: 1080,
	UniProxyProto.CLIENT_HTTP : 8080,
	UniProxyProto.CLIENT_SSL_HTTP :8443,
	UniProxyProto.CLIENT_WSNET: 8700,
	UniProxyProto.CLIENT_WSNETTEST: 8700,
	UniProxyProto.CLIENT_WSNETWS:8700,
	UniProxyProto.CLIENT_SSL_WSNETWS:8765,
	UniProxyProto.CLIENT_WSNETDIRECT:8700,
}


def urlparam_proto(x):
	return proxyshort_to_type[x.upper()]

uniproxytarget_urlparams_param2var = {
	'type' : ('protocol', [stru, urlparam_proto]),
	'host' : ('server_ip', [str]),
	'server' : ('server_ip', [str]),
	'port' : ('server_port', [int]),
	'bind' : ('is_bind', [bool]),
	'timeout': ('timeout', [int]),
	'etimeout' : ('endpoint_timeout', [int]),
	'bsize' : ('buffer_size', [int]),
	'user' : ('username', [str]),
	'pass' : ('password', [str]),
	#'authtype' : ('authtype', [SOCKS5Method]),
	'userid' : ('userid', [str]),
	'agentid' : ('agentid', [str]),
}

class UniProxyTarget:
	def __init__(self):
		self.server_ip:str = None
		self.server_port:int = None
		self.agentid:str = None
		self.protocol:UniProxyProto = None
		self.timeout:int = 10
		self.ssl_ctx:ssl.SSLContext = None
		self.credential = None
		self.endpoint_ip:str = None
		self.endpoint_port:int = None
		self.wsnet_reuse:bool = False
		self.userid = os.urandom(4).hex().encode('ascii')
		self.customproxyfactory = None

		self.only_open = False #These params used for security testing only! 
		self.only_auth = False #These params used for security testing only!
		self.only_bind = False #These params used for security testing only!
	
	def get_sname(self):
		return '%s:%s' % (self.server_ip, self.server_port)

	def get_tname(self):
		return '%s:%s' % (self.endpoint_ip, self.endpoint_port)

	def __repr__(self):
		return str(self.__dict__)

	def __str__(self):
		t = '==== UniProxyTarget ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t

	def __deepcopy__(self, memo=None):
		proxy = UniProxyTarget()
		proxy.server_ip = copy.deepcopy(self.server_ip)
		proxy.server_port = copy.deepcopy(self.server_port)
		proxy.agentid = copy.deepcopy(self.agentid)
		proxy.protocol = copy.deepcopy(self.protocol)
		proxy.timeout = copy.deepcopy(self.timeout)
		proxy.ssl_ctx = copy.deepcopy(self.ssl_ctx) #this will definitely fail!!!
		proxy.credential = copy.deepcopy(self.credential)
		proxy.endpoint_ip = copy.deepcopy(self.endpoint_ip)
		proxy.endpoint_port = copy.deepcopy(self.endpoint_port)
		proxy.wsnet_reuse = copy.deepcopy(self.wsnet_reuse)
		proxy.userid = copy.deepcopy(self.userid)
		self.only_open = copy.deepcopy(self.only_open) 
		self.only_auth = copy.deepcopy(self.only_auth)
		self.only_bind = copy.deepcopy(self.only_bind)
		proxy.customproxyfactory = self.customproxyfactory
		return proxy

	@staticmethod
	def from_url_params(query, hostname, endpoint_port = None):
		lastproxy = UniProxyTarget()
		lastproxy.endpoint_ip = hostname
		lastproxy.endpoint_port = int(endpoint_port)
		if query is not None:
			proxycounts = [0]
			proxynums = {'0' : None}
			for k in query:
				if k.startswith('proxy'):
					try:
						int(k[5])
						if k[5] not in proxynums:
							proxynums[k[5]] = None
							proxycounts.append(int(k[5]))
					except Exception as e:
						#print(e)
						pass
			#print(proxynums)
			#print(proxycounts)
			if len(proxycounts) != len(proxynums):
				raise Exception('proxyies are not in sequential order! ERROR!')

			proxycounts.sort()
			firstiter = True
			prevproxy = lastproxy
			for i in proxycounts[::-1]:
				pdata = UniProxyTarget()
				if firstiter is True:
					firstiter = False
					pdata = lastproxy
				else:
					pdata.endpoint_ip = prevproxy.server_ip
					pdata.endpoint_port = prevproxy.server_port
					prevproxy = pdata
				startstring = 'proxy%s' % i
				if i == 0:
					startstring = 'proxy'
				for k in query:
					if k.startswith(startstring):
						startpos = 6
						if i == 0:
							startpos = 5
												
						if k[startpos:] in uniproxytarget_urlparams_param2var:
							data = query[k][0]
							for c in uniproxytarget_urlparams_param2var[k[startpos:]][1]:
								#print(c)
								data = c(data)

							setattr(
								pdata, 
								uniproxytarget_urlparams_param2var[k[startpos:]][0], 
								data
							)
				proxynums[str(i)] = pdata

		#if len(proxynums) > 1:
		#	for k in proxynums:
		#		if proxynums[k].version in sockssslversions:
		#			raise Exception('SSL in proxy chaining not supported! That would be a lot of work...')
		#else:
		#	if proxynums['0'].version in sockssslversions:
		#		proxynums['0'].ssl_ctx = ssl.create_default_context()

		
		#for k in proxynums:
		#	proxynums[k].sanity_check()
		
		targets = []
		for i in proxycounts:
			targets.append(proxynums[str(i)])

		return targets

	@staticmethod
	def from_url(url_str, endpoint_port = None):
		"""

		"""
		url = urlparse(url_str)
		endpoint_ip = url.hostname
		if url.port:
			endpoint_port = int(url.port)
		else:
			endpoint_port = int(endpoint_port)
		query = None
		if url.query is not None:
			query = parse_qs(url.query)
		return UniProxyTarget.from_url_params(query, endpoint_ip, endpoint_port)

	@staticmethod
	def from_url_full(url_str, endpoint_ip, endpoint_port):
		"""socks5+password://TEST\\Administrator:Password!1@127.0.0.1"""
		result = []
		if isinstance(url_str, list):
			for url in url_str[::-1]:
				res = UniProxyTarget.from_url_full(url, endpoint_ip, endpoint_port)
				result += res
				endpoint_ip   = res[0].server_ip
				endpoint_port = res[0].server_port
			return result[::-1]
		
		url = urlparse(url_str)
		proto, auth = url.scheme.upper().split('+')
		protocol = proxyshort_to_type[proto]

		query = None
		if url.query is not None:
			query = parse_qs(url.query)
		
		params = {}
		for k in query:
			if k in uniproxytarget_urlparams_param2var:
				data = query[k][0]
				for c in uniproxytarget_urlparams_param2var[k][1]:
					data = c(data)
					params[k] = data
		

		credential = None
		if url.username is not None or url.password is not None:
			credential = (url.username, url.password)

		pt = UniProxyTarget()
		pt.server_ip = url.hostname
		pt.server_port = url.port if url.port is not None else proxyshort_protocol_defport[protocol]
		pt.protocol= protocol
		pt.endpoint_ip = endpoint_ip
		pt.endpoint_port = endpoint_port
		pt.credential = credential
		pt.agentid = params.get('agentid')
		pt.timeout = params.get('timeout', 10)

		return [pt]
		
if __name__ == '__main__':
	a = "socks5+password://TEST\\Administrator:Password!1@127.0.0.1"
	b = "socks5+password://TEST\\Administrator:Password!1@127.0.0.1"
	c = "socks5+password://TEST\\Administrator:Password!1@127.0.0.1"

	res = UniProxyTarget.from_url_full([a,b,c], None, None)
	for r in res:
		
		print(r)