

from urllib.parse import urlparse, parse_qs
import ssl


from asysocks.common.credentials import SocksCredential
from asysocks.common.constants import SocksServerVersion, SocksProtocol, SOCKS5Method
from asysocks.common.target import SocksTarget

def stru(x):
	return str(x).upper()
	
clienturl_param2var = {
	'type' : ('version', [stru, SocksServerVersion]),
	'host' : ('server_ip', [str]),
	'server' : ('server_ip', [str]),
	'port' : ('server_port', [int]),
	'bind' : ('is_bind', [bool]),
	'proto': ('proto', [SocksProtocol]),
	'timeout': ('timeout', [int]),
	'etimeout' : ('endpoint_timeout', [int]),
	'bsize' : ('buffer_size', [int]),
	'user' : ('username', [str]),
	'pass' : ('password', [str]),
	'authtype' : ('authtype', [SOCKS5Method]),
	'userid' : ('userid', [str]),
	'agentid' : ('agentid', [str]),

}

clienturl_url2var = {
	'isbind' : ('is_bind', bool),
	'proto' : ('proto', SocksProtocol),
	'timeout' : ('endpoint_timeout', int),
	'buffersize' : ('buffer_size', int),
	'userid' : ('userid', str),
	'agentid' : ('agentid', str),
}

sockssslversions = {
	SocksServerVersion.SOCKS5S : 1,
	SocksServerVersion.SOCKS4S : 1,
	SocksServerVersion.HTTPS : 1,
}

class SocksClientURL:
	def __init__(self):
		self.version = None
		self.server_ip = None
		self.server_port = 1080
		self.is_bind = False
		self.proto = SocksProtocol.TCP
		self.timeout = 10
		self.buffer_size = 4096
		self.ssl_ctx = None
		self.wsnet_reuse = False
		
		self.endpoint_ip = None
		self.endpoint_port = None
		self.endpoint_timeout = None
		
		self.username = None
		self.password = None
		self.agentid = None


	def get_creds(self):
		if self.username is None:
			return None
		creds = SocksCredential()
		creds.username = self.username
		creds.password = self.password
		return creds

	def get_target(self):
		target = SocksTarget()
		target.version = self.version
		target.server_ip = self.server_ip
		target.server_port = self.server_port
		target.is_bind = self.is_bind
		target.proto = self.proto
		target.timeout = self.timeout
		target.buffer_size = self.buffer_size
		target.endpoint_ip = self.endpoint_ip
		target.endpoint_port = self.endpoint_port
		target.endpoint_timeout = self.endpoint_timeout
		target.ssl_ctx = self.ssl_ctx
		target.credential = self.get_creds()
		target.agentid = self.agentid
		target.wsnet_reuse = self.wsnet_reuse
		return target

	def sanity_check(self):
		if self.version != SocksServerVersion.WSNET:
			if self.server_ip is None:
				raise Exception('SOCKS server IP is missing!')
			if self.server_port is None:
				raise Exception('SOCKS server port is missing!')

		if self.buffer_size <= 0:
			raise Exception('buffer_size is too low! %s' % self.buffer_size)
		if self.endpoint_ip is None:
			raise Exception('Endpoint IP address is missing!')
		#if self.endpoint_port is None:
		#	raise Exception('Endpoint port is missing!')

	@staticmethod
	def from_urls(urls, endpoint_ip = None, endpoint_port = None):
		proxylist = []
		first = True
		prevtarget = None
		for url in urls[::-1]:
			res = SocksClientURL.from_url(url).get_target()
			if first is True:
				res.endpoint_ip = endpoint_ip
				res.endpoint_port = endpoint_port
				first = False
			else:
				res.endpoint_ip = prevtarget.server_ip
				res.endpoint_port = prevtarget.server_port
			prevtarget = res
			proxylist.append(res)

		return proxylist[::-1]

	@staticmethod
	def from_url(url_str):
		res = SocksClientURL()
		url_e = urlparse(url_str)

		res.version = SocksServerVersion(url_e.scheme.upper())
		res.server_ip = url_e.hostname
		if url_e.port is not None:
			res.server_port = int(url_e.port)
		elif res.version == SocksServerVersion.HTTP:
			res.server_port = 8080
		elif res.version == SocksServerVersion.HTTPS:
			res.server_port = 8443
		elif res.version == SocksServerVersion.SOCKS5:
			res.server_port = 1080
		elif res.version == SocksServerVersion.SOCKS5S:
			res.server_port = 1080
		elif res.version == SocksServerVersion.SOCKS4:
			res.server_port = 1080
		elif res.version == SocksServerVersion.SOCKS4S:
			res.server_port = 1080
		elif res.version == SocksServerVersion.SOCKS4A:
			res.server_port = 1080
		elif res.version == SocksServerVersion.SOCKS4AS:
			res.server_port = 1080
		elif res.version == SocksServerVersion.WSNET:
			res.server_port = None

		res.username = url_e.username
		res.password = url_e.password
		if res.version in sockssslversions:
			res.ssl_ctx = ssl.create_default_context()
		
		#print(url_e)
		if url_e.query is not None:
			query = parse_qs(url_e.query)
			for k in query:
				if k in clienturl_url2var:
					pname = clienturl_url2var[k][0]
					param = clienturl_url2var[k][1](query[k][0])
					setattr(res, pname, param)
		
		return res

	@staticmethod
	def from_params(url_str):
		"""

		"""
		lastproxy = SocksClientURL()
		url = urlparse(url_str)
		lastproxy.endpoint_ip = url.hostname
		if url.port:
			lastproxy.endpoint_port = int(url.port)
		if url.query is not None:
			query = parse_qs(url.query)

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
				pdata = SocksClientURL()
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
												
						if k[startpos:] in clienturl_param2var:
							data = query[k][0]
							for c in clienturl_param2var[k[startpos:]][1]:
								#print(c)
								data = c(data)

							setattr(
								pdata, 
								clienturl_param2var[k[startpos:]][0], 
								data
							)
				proxynums[str(i)] = pdata

		if len(proxynums) > 1:
			for k in proxynums:
				if proxynums[k].version in sockssslversions:
					raise Exception('SSL in proxy chaining not supported! That would be a lot of work...')
		else:
			if proxynums['0'].version in sockssslversions:
				proxynums['0'].ssl_ctx = ssl.create_default_context()

		
		for k in proxynums:
			proxynums[k].sanity_check()
		
		targets = []
		for i in proxycounts:
			targets.append(proxynums[str(i)].get_target())

		return targets



if __name__ == '__main__':

	url = 'http://alma.com:80/haha?proxytype=socks5&proxyport=66&proxyhost=127.0.0.1'
	url = 'http://alma.com:80/haha?proxytype=socks5&proxyport=66&proxyhost=127.0.0.1&proxy1type=socks4&proxy1port=9876&proxy1host=255.255.0.0'
	#url = 'http://alma.com:80/haha?proxytype=socks5&proxyport=66&proxyhost=127.0.0.1&proxy2type=socks4&proxy2port=9876&proxy2host=255.255.0.0'
	#url = 'http://alma.com:80/haha?proxytype=socks5&proxyport=66&proxyhost=127.0.0.1&proxy2type=socks4&proxy2port=9876&proxy2host=255.255.0.0&proxy1type=socks5s&proxy1port=6666&proxy1host=127.255.0.0'
	url = 'http://alma.com:80/haha?proxytype=socks5&proxyport=66&proxyhost=127.0.0.1&proxy2type=socks4&proxy2port=9876&proxy2host=255.255.0.0&proxy1type=socks5&proxy1port=6666&proxy1host=127.255.0.0'
	
	o = urlparse(url)
	res = SocksClientURL.from_params(url)
	print('aaaaaaaaaaaaaaaaaaaa')
	for target in res:
		print(target.__dict__)

						