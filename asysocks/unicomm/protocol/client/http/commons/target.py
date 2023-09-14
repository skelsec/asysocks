from os import stat
from sqlite3 import connect
from asysocks.unicomm.common.target import UniTarget, UniProto, unitarget_url_params
from urllib.parse import urlparse, parse_qs, urljoin, urlencode, urlunparse
from asysocks.unicomm.utils.paramprocessor import str_one, int_one, bool_one

class HTTPTarget(UniTarget):
	def __init__(self, ip, port = 80, protocol = UniProto.CLIENT_TCP, path = None, query = None, proxies = None, timeout = 10, dns:str=None, dc_ip:str = None, domain:str = None, hostname:str = None, ssl_ctx = None):
		UniTarget.__init__(self, ip, port, protocol, timeout, hostname = hostname, ssl_ctx= ssl_ctx, proxies = proxies, domain = domain, dc_ip = dc_ip, dns=dns)
		self.path = path
		self.query = query

	def to_target_string(self):
		return 'HTTP/%s@%s' % (self.get_hostname_or_ip(), self.domain)  #HTTP/WIN2019AD.test.corp @ TEST.CORP
	
	def get_host(self):
		if self.protocol == UniProto.CLIENT_SSL_TCP:
			proto = 'https'
		elif self.protocol == UniProto.CLIENT_TCP:
			proto = 'http'
		if proto == 'http' and self.port == 80:
			return '%s://%s' % (proto, self.get_hostname_or_ip())
		elif proto == 'https' and self.port == 443:
			return '%s://%s' % (proto, self.get_hostname_or_ip())
		return '%s://%s:%s' % (proto, self.get_hostname_or_ip(), self.port)
	
	def get_url(self):
		url = urljoin(self.get_host(), self.path)
		if self.query is not None and len(self.query) > 0:
			parsed_url = urlparse(url)
			new_parsed_url = parsed_url._replace(query=self.query)
			url = urlunparse(new_parsed_url)
		return url
	
	def is_ssl(self):
		return self.protocol == UniProto.CLIENT_SSL_TCP
	
	@staticmethod
	def from_url(connection_url):
		url_e = urlparse(connection_url)
		schemes = []
		for item in url_e.scheme.upper().split('+'):
			schemes.append(item.replace('-','_'))
		if schemes[0] == 'HTTP':
			protocol = UniProto.CLIENT_TCP
			port = 80
		elif schemes[0] == 'HTTPS':
			protocol = UniProto.CLIENT_SSL_TCP
			port = 443
		else:
			raise Exception('Unknown protocol! %s' % schemes[0])
		
		if url_e.port:
			port = url_e.port
		if port is None:
			raise Exception('Port must be provided!')
		
		path = None
		if url_e.path not in ['/', '', None]:
			path = url_e.path
		
		unitarget, extraparams = UniTarget.from_url(connection_url, protocol, port, {})

		#removing query params
		params_to_remove = {'dc': 1, 'dns': 1, 'dcip': 1}
		params_to_remove.update(unitarget_url_params)
		params_to_remove.update(extraparams)

		parsed_query = parse_qs(url_e.query)
		for param in parsed_query:
			if param.startswith('proxy') is True:
				params_to_remove[param] = 1
		
		for param in params_to_remove:
			parsed_query.pop(param, None)
		
		new_query = urlencode(parsed_query, doseq=True)

		target = HTTPTarget(
			unitarget.ip, 
			port = unitarget.port, 
			protocol = unitarget.protocol, 
			path = path,
			query=new_query,
			proxies = unitarget.proxies, 
			timeout = unitarget.timeout, 
			dns = unitarget.dns, 
			dc_ip = unitarget.dc_ip, 
			domain = unitarget.domain, 
			hostname = unitarget.hostname,
			ssl_ctx = unitarget.ssl_ctx,
		)
		return target
	
	def __str__(self):
		t = '==== HTTPTarget ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
	
if __name__ == '__main__':
	test = [
		#please create random URLs for testing
		'http://test.corp:80',
		'https://test.corp:80',
		'http://test.corp:443',
		'https://test.corp:443',
		'http://test.corp:80/',
		'https://test.corp:80/',
		'http://test.corp:443/',
		'https://test.corp:443/',
		'http://test.corp:80/path',
		'https://test.corp:80/path',
		'http://test.corp:443/path',
		'https://test.corp:443/path',
		'http://test.corp:80/path?query',
		'https://test.corp:80/path?query',
		'http://test.corp:443/path?query',
		'https://test.corp:443/path?query',
		'http://test.corp:80/path?query=1',
		'https://test.corp:80/path?query=1',
		'http://test.corp:443/path?query=1',
		'https://test.corp:443/path?query=1',
		'http://test.corp:80/path?query=1&query2=2',
		'https://test.corp:80/path?query=1&query2=2',
		'http://test.corp:443/path?query=1&query2=2',
		'https://test.corp:443/path?query=1&query2=2',
		'http://test.corp:80/path?query=1&query2=2&query3=3',
		'https://test.corp:80/path?query=1&query2=2&query3=3',
		'http://test.corp:443/path?query=1&query2=2&query3=3',
		'https://test.corp:443/path?query=1&query2=2&query3=3',
		'http://test.corp:80/path?query=1&query2=2&query3=3&query4=4',
		'https://test.corp:80/path?query=1&query2=2&query3=3&query4=4',
		'http+ntlm-password://test.corp:443/path?query=1&query2=2&query3=3&query4',
		'http+ntlm-password://test.corp:443/path?query=1&query2=2&query3=3&proxy=1'
	]
	for url in test:
		res = HTTPTarget.from_url(url)
		print(res)
		print('Original: %s' % url)
		print('Reconstr: %s' % res.get_url())
		print(res.get_url() == url)
		print('------------------')