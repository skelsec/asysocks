from os import stat
import ssl
import copy
import enum
import ipaddress
from typing import Callable, Dict, List
from urllib.parse import urlparse, parse_qs

from asysocks.unicomm.common.unissl import UniSSL
from asysocks.unicomm.common.proxy import UniProxyProto, UniProxyTarget
from asysocks.unicomm.utils.paramprocessor import str_one, int_one, bool_one

class UniProto(enum.Enum):
	CLIENT_TCP = 1
	CLIENT_SSL_TCP = 2
	CLIENT_UDP = 3
	CLIENT_DTLS = 4
	CLIENT_QUIC = 5
	SERVER_TCP = 6
	SERVER_SSL_TCP = 7
	SERVER_UDP = 8

unitarget_url_params = {
	'dc' : str_one,
	'timeout' : int_one,
	'serverip' : str_one,
	'dns' : str_one,
	'privport' : bool_one,
}

class UniTarget:
	def __init__(self, ip:str, port:int, protocol:UniProto, timeout:int=5, ssl_ctx:UniSSL=None, hostname:str = None, dc_ip:str = None, domain:str = None, proxies:List[UniProxyTarget] = None, dns:str = None, use_privileged_source_port:bool = False):
		self.hostname = hostname
		self.port = port
		self.protocol = protocol
		self.timeout = timeout
		self.ssl_ctx = ssl_ctx
		self.dc_ip = dc_ip
		self.domain = domain
		self.dns = dns
		self.use_privileged_source_port = use_privileged_source_port
		self.proxies:List[UniProxyTarget] = proxies
		if proxies is None:
			self.proxies = []

		try:
			ipaddress.ip_address(ip)
			self.ip = ip
		except:
			if ip is not None:
				self.hostname = ip
			self.ip = None
		
		try:
			ipaddress.ip_address(hostname)
			self.ip = hostname
		except:
			if hostname is not None:
				self.hostname = hostname
		
		if ip is None and hostname is None:
			raise Exception('Both IP and Hostname can\'t be none!')

		self.__update_proxy()

	def __update_proxy(self):
		if len(self.proxies) == 0:
			return
		self.proxies[-1].endpoint_ip = self.get_hostname_or_ip()
		self.proxies[-1].endpoint_port = self.port

	@staticmethod
	def get_help(helptype:str = 'url'):
		if helptype == 'url':
			return 'Connection related parameters -query params-:\n' + \
				'\ttimeout - int - connection timeout in seconds\n' + \
				'\tdc - str - domain controller IP address (KERBEROS)\n' + \
				'\tserverip - str - server IP address (if different from what your DNS resolver would say)\n' + \
				'\tdns - str - DNS server IP address (not used)\n' + \
				'\tsslverify - bool - SSL/TLS verify server certificate\n' + \
				'\tsslcert - str - SSL/TLS certificate path\n' + \
				'\tsslkey - str - SSL/TLS key path\n' + \
				'\tsslpassword - str - SSL/TLS key password\n' +\
				'\t=== PROXY PARAMETERS ===\n' + \
				'\tEach proxy needs at least "proxytype", "proxyhost" and "proxyport" defined!\n' +\
				'\tProxy parameters can be repeated to add multiple proxies, just change the prefix to "proxy1" "proxy2" ...\n'+\
				'\tproxytype - str - Available PROXY protocols: http, socks4, socks5\n\n' + \
				'\tproxyusername - str - proxy username\n' + \
				'\tproxypassword - str - proxy password\n' + \
				'\tproxytimeout - int - proxy connection timeout in seconds\n' + \
				'\tproxyhost - str - proxy server IP address\n' + \
				'\tproxyport - int - proxy port\n' + \
				'\tproxyssl - bool - proxy SSL/TLS\n' + \
				'\tproxysslverify - bool - proxy SSL/TLS verification\n' + \
				'\tproxysslcert - str - proxy SSL/TLS certificate path\n' + \
				'\tproxysslkey - str - proxy SSL/TLS key path\n' + \
				'\tproxysslkey_password - str - proxy SSL/TLS key password\n'
				


	def get_newtarget(self, ip, port, hostname = None):
		return UniTarget(ip, port, self.protocol, self.timeout, ssl_ctx = self.ssl_ctx, hostname = hostname, dc_ip = self.dc_ip, domain = self.domain, proxies=copy.deepcopy(self.proxies))

	def get_ssl_context(self, protocol = None):
		if self.ssl_ctx is None:
			is_server = True if self.protocol in [UniProto.SERVER_TCP, UniProto.SERVER_SSL_TCP, UniProto.SERVER_UDP] else False
			self.ssl_ctx = UniSSL.get_noverify_context(is_server)
		
		return self.ssl_ctx.get_ssl_context(protocol)
		

	def get_hostname(self):
		return self.hostname
	
	def set_hostname_or_ip(self, ip):
		try:
			self.ip = str(ipaddress.ip_address(ip))
		except:
			self.hostname = ip
			self.ip = ip
	
	def get_ip_or_hostname(self):
		if self.ip is not None:
			return self.ip
		return self.hostname

	def get_hostname_or_ip(self):
		if self.hostname is not None:
			return self.hostname
		return self.ip

	@staticmethod
	def from_url(connection_url, protocol:UniProto, port:int = None, extraparams:Dict[str, Callable] = {}):
		url_e = urlparse(connection_url)
		domain = None
		if url_e.username is not None:
			if url_e.username.find('\\') != -1:
				domain, username = url_e.username.split('\\')
				if domain == '.':
					domain = None
			else:
				domain = None
				username = url_e.username

		ip = url_e.hostname
		if url_e.port is None and port is None:
			raise Exception('Port must be provided!')
		if url_e.port and port is None:
			port = url_e.port
		
		params = dict.fromkeys(unitarget_url_params.keys(),None)
		extra = dict.fromkeys(extraparams.keys(),None)
		proxy_present = False
		if url_e.query is not None:
			query = parse_qs(url_e.query)
			for k in query:
				if k.startswith('proxy') is True:
					proxy_present = True
				if k in unitarget_url_params:
					params[k] = unitarget_url_params[k](query[k])
				if k in extraparams:
					extra[k] = extraparams[k](query[k])
		
		hostname = None
		if ip is not None:
			try:
				ipaddress.ip_address(ip)
			except:
				hostname = ip
				ip = None
		
		if params['serverip'] is not None:
			ip = params['serverip']
		
		proxies = None
		if proxy_present is True:
			proxies = UniProxyTarget.from_url(connection_url, endpoint_port=port)
		
		timeout = params['timeout'] if params['timeout'] is not None else 5
		sslctx = UniSSL.from_url(connection_url)
		return UniTarget(
			ip,
			port,
			protocol,
			timeout = timeout,
			hostname = hostname,
			ssl_ctx=sslctx,
			dc_ip = params['dc'],
			domain=domain,
			proxies=proxies,
			dns=params['dns'],
			use_privileged_source_port=params['privport']
		), extra

	def get_preproxy(self):
		if len(self.proxies) > 1:
			lproxy = self.proxies[-1]
			lproto=UniProto.CLIENT_TCP
			return UniTarget(lproxy.server_ip, lproxy.server_port, protocol = lproto, proxies=self.proxies[:-1])
		
		return self
		
			
	
	def __str__(self):
		t = '==== UniTarget ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
		return t