import os
import ssl
from urllib.parse import urlparse, parse_qs
from asysocks.unicomm.utils.paramprocessor import str_one, int_one, bool_one
from contextlib import contextmanager
from tempfile import NamedTemporaryFile

unissl_url_param2var = {
	'ca' : ('cacert', [str]),
	'cert' : ('certfile', [str]),
	'key' : ('keyfile', [str]),
	'password' : ('password', [str]),
	'verify' : ('verify', [bool]),
}

class UniSSL:
	"""This class was necessary to be able to create duplicates of ssl contexts, which is not possible with the ssl.SSLContext class."""
	def __init__(self, certfile:str = None, keyfile:str = None, cacert:str = None, password:str = None, verify:bool = False):
		self.protocol = ssl.PROTOCOL_TLS
		self.cacert:str = cacert
		self.keyfile:str = keyfile
		self.certfile:str = certfile
		self.password:str = password
		self.verify:bool = verify
		self.__cacertfilename = None
		self.__keyfilename = None
		self.__certfilename = None
		self.__startup()
	
	def __startup(self):
		if self.keyfile is not None:
			if isinstance(self.keyfile, str):
				# is the keyfile a p12 or pfx file?
				if self.keyfile.endswith('.pfx') or self.keyfile.endswith('.p12'):
					self.pfx_to_pem(self.keyfile, self.password)
					
				else:
					#is the keyfile an actual file?
					try:
						with open(self.keyfile, 'rb') as f:
							pass
						self.__keyfilename = self.keyfile
					except:
						# is the keyfile a string?
						self.__keyfilename = 'key_%s.pem' % os.urandom(4).hex()
						with open(self.__keyfilename, 'w', newline='') as f:
							f.write(self.keyfile)
			else:
				# is the keyfile a bytes object?
				self.__keyfilename = 'key_%s.pem' % os.urandom(4).hex()
				with open(self.__keyfilename, 'wb') as f:
					f.write(self.keyfile)
		
		if self.certfile is not None:
			if isinstance(self.certfile, str):
				# is the certfile a p12 or pfx file?
				if self.certfile.endswith('.pfx') or self.certfile.endswith('.p12'):
					self.pfx_to_pem(self.certfile, self.password)
					
				else:
					#is the certfile an actual file?
					try:
						with open(self.certfile, 'rb') as f:
							pass
						self.__certfilename = self.certfile
					except:
						# is the certfile a string?
						self.__certfilename = 'cert_%s.pem' % os.urandom(4).hex()
						with open(self.__certfilename, 'w', newline='') as f:
							f.write(self.certfile)
			else:
				# is the certfile a bytes object?
				self.__certfilename = 'key_%s.pem' % os.urandom(4).hex()
				with open(self.__certfilename, 'wb') as f:
					f.write(self.certfile)
		
		if self.cacert is not None:
			if isinstance(self.cacert, str):
				try:
					with open(self.cacert, 'rb') as f:
						pass
					self.__cacertfilename = self.cacert
				except:
					self.__cacertfilename = 'cacert_%s.pem' % os.urandom(4).hex()
					with open(self.__cacertfilename, 'w', newline='') as f:
						f.write(self.cacert)
			else:
				self.__cacertfilename = 'cacert_%s.pem' % os.urandom(4).hex()
				with open(self.__cacertfilename, 'wb') as f:
					f.write(self.cacert)
	
	def pfx_to_pem(self, pfx_path, pfx_password):
		#https://gist.github.com/erikbern/756b1d8df2d1487497d29b90e81f8068
		from pathlib import Path
		from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
		from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
		''' Decrypts the .pfx file to be used with requests. '''
		pfx = Path(pfx_path).read_bytes()
		private_key, main_cert, add_certs = load_key_and_certificates(pfx, pfx_password.encode('utf-8'), None)
		suffix = '%s.pem' % os.urandom(4).hex()
		self.__keyfilename = 'key_%s' % suffix
		self.__certfilename = 'cert_%s' % suffix
		with open(self.__keyfilename, 'wb') as f:
			f.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
		with open(self.__certfilename, 'wb') as f:
			f.write(main_cert.public_bytes(Encoding.PEM))
		if len(add_certs) > 0:
			self.__cacertfilename = 'cacert_%s' % suffix
			with open(self.__cacertfilename, 'wb') as f:
				for ca in add_certs:
					f.write(ca.public_bytes(Encoding.PEM))

	@staticmethod
	def get_noverify_context(is_server=False, hostname = 'localhost'):
		"""Returns a generic SSL context that does not verify the certificate."""
		if is_server is True:
			from asysocks.unicomm.utils.genselfsigned import generate_selfsigned_cert
			server_certfile, server_keyfile = generate_selfsigned_cert(hostname)
			return UniSSL(server_certfile, server_keyfile, None, verify=False)
		
		return UniSSL(verify=False)			
	
	def get_ssl_context(self, protocol = ssl.PROTOCOL_TLS_CLIENT):
		try:
			self.__startup()
			ssl_ctx = ssl.SSLContext(protocol)
			if self.__certfilename is not None:
				ssl_ctx.load_cert_chain(certfile=self.__certfilename, keyfile=self.__keyfilename, password=self.password)
			
			if self.verify is False:
				ssl_ctx.check_hostname = False
				ssl_ctx.verify_mode = ssl.CERT_NONE
			else:
				if self.cacert is not None:
					ssl_ctx.load_verify_locations(cafile=self.__cacertfilename)
				else:
					ssl_ctx.load_default_certs(purpose=ssl.Purpose.SERVER_AUTH)
			return ssl_ctx
		finally:
			self.__cleanup()
	
	@staticmethod
	def from_url(url):
		url_e = urlparse(url)
		params = {}
		if url_e.query is not None:
			query = parse_qs(url_e.query)
			for k in query:
				if k.startswith('ssl') is False:
					continue
				params[k] = query[k]
		return UniSSL.from_urlparams(params)

	@staticmethod
	def from_urlparams(params):
		finalparams = {}
		for k in params:
			if k.startswith('ssl_') is True:
				pname = k[4:]
			elif k.startswith('ssl') is True:
				pname = k[3:]
			else:
				continue
				
			if pname in unissl_url_param2var:
				finalparams[unissl_url_param2var[pname][0]] = unissl_url_param2var[pname][1][0](params[k][0])
		if len(finalparams) == 0:
			return None
		return UniSSL(**finalparams)

	def __cleanup(self):
		if self.__certfilename != self.certfile:
			try:
				os.remove(self.__certfilename)
			except:
				pass
		if self.__keyfilename != self.keyfile:
			try:
				os.remove(self.__keyfilename)
			except:
				pass
		if self.__cacertfilename != self.cacert:
			try:
				os.remove(self.__cacertfilename)
			except:
				pass

	def __str__(self):
		return 'UniSSL(certfile=%s, keyfile=%s, cacert=%s, verify=%s, protocol=%s)' % (self.certfile, self.keyfile, self.cacert, self.verify, self.protocol)

	def __del__(self):
		self.__cleanup()

def main():
	url = 'https://www.google.com/?ssl_cert=cert.pem&ssl_key=key.pem&ssl_cacert=cacert.pem&ssl_verify=False'
	ssl = UniSSL.from_url(url)
	print(ssl)

if __name__ == '__main__':
	main()