
import os
import asyncio
import datetime
import uuid
import glob
import tempfile
import logging
import hashlib
import ssl



from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

logger = logging.getLogger('asysocks.certmanager')
handler = logging.StreamHandler()
formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class CertManager:
	def __init__(self, ca_cert = None, ca_key = None, cache_dir = None, ca_cert_file = None, ca_key_file = None, ca_key_file_pw = None):
		self.ca_cert_file = ca_cert_file
		self.ca_cert = ca_cert
		self.ca_key = ca_key
		self.ca_key_file = ca_key_file
		self.ca_key_file_pw = ca_key_file_pw
		self.cache_dir = cache_dir
		self.ca = None

		self.setup()

	def setup(self):
		ca_cert_data = None
		ca_key_data = None

		if self.cache_dir is None:
			path = os.path.join(tempfile.gettempdir(), 'certstore')
			os.makedirs(path, exist_ok=True)
			self.cache_dir = path

		if self.ca_cert_file is None and self.ca_cert is None:
			self.ca_cert_file = os.path.join(self.cache_dir, 'cacert.pem')
			
		if self.ca_key_file is None and self.ca_key is None:
			self.ca_key_file = os.path.join(self.cache_dir, 'cakey.pem')
				

		if self.ca_cert_file is not None:
			try:
				with open(self.ca_cert_file, 'rb') as f:
					ca_cert_data = f.read()
			except:
				pass
		
		if self.ca_key_file is not None:
			try:
				with open(self.ca_key_file, 'rb') as f:
					ca_key_data = f.read()
			except:
				pass
		
		if ca_cert_data is None or ca_key_data is None:
			self.intialize_certstore()

		else:
			self.ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())
			self.ca_key = serialization.load_pem_private_key(ca_key_data, self.ca_key_file_pw, backend=default_backend())
	
	def intialize_certstore(self, cn = 'asysocks', on = 'asysocks', ou = 'asysocks', key_exp = 65537, key_size = 2048):
		ca_cert, ca_key, err = CertManager.generate_ca(cn = cn, on = on, ou = ou, key_exp = key_exp, key_size = key_size)
		if err is not None:
			raise err
		
		cname = 'cacert.pem'
		kname = 'cakey.pem'

		with open(os.path.join(self.cache_dir, cname), 'wb') as f:
			f.write(ca_cert)
		
		with open(os.path.join(self.cache_dir, kname), 'wb') as f:
			f.write(ca_key)

		self.ca_cert = x509.load_pem_x509_certificate(ca_cert, default_backend())
		self.ca_key = serialization.load_pem_private_key(ca_key, self.ca_key_file_pw, backend=default_backend())


	def store_to_cache(self, new_cert, new_key, hostname = None):
		cert = x509.load_pem_x509_certificate(new_cert, default_backend())
		
		if hostname is not None:
			bname = bname = '%s_%s' % (cert.serial_number, hostname)
		else:
			bname = '%s_%s' % (cert.serial_number, hashlib.sha1(cert.subject.rfc4514_string().encode()).hexdigest())
		cname = '%s_%s.pem' % (bname, 'cert')
		kname = '%s_%s.pem' % (bname, 'key')

		with open(os.path.join(self.cache_dir, cname), 'wb') as f:
			f.write(new_cert)
		
		with open(os.path.join(self.cache_dir, kname), 'wb') as f:
			f.write(new_key)

		return os.path.join(self.cache_dir, cname), os.path.join(self.cache_dir, kname)

	def load_from_cache(self, hostname = None, cert_der_data = None, serial = None, subject = None, ret_file_path = True):
		cert_filename = None
		key_filename = None


		if cert_der_data is not None:
			cert = x509.load_der_x509_certificate(cert_der_data, default_backend())
			serial = cert.serial_number


		for filename in glob.glob(os.path.join(self.cache_dir, '*.pem')):
			basename = os.path.basename(filename)
			if serial is not None and basename.startswith(str(serial)):
				if basename.endswith('_key.pem'):
					key_filename = filename
				elif basename.endswith('_cert.pem'):
					cert_filename = filename

			elif hostname is not None and basename.find('_%s_' % hostname) != -1:
				if basename.endswith('_key.pem'):
					key_filename = filename
				elif basename.endswith('_cert.pem'):
					cert_filename = filename


		if cert_filename is None or key_filename is None:
			return None, None
		
		if ret_file_path is True:
			return os.path.join(self.cache_dir, cert_filename), os.path.join(self.cache_dir, key_filename)

		with open(cert_filename, 'r') as f:
			certdata = f.read()
		with open(key_filename, 'r') as f:
			keydata = f.read()

		return certdata, keydata

	def resign_certificate(self, cert, is_binary = True):
		try:
			if is_binary is True:
				old_cert = x509.load_der_x509_certificate(cert, default_backend())
			else:
				old_cert = x509.load_pem_x509_certificate(cert, default_backend())

			# TODO: generate the same type of key with the same strength as the original cert has
			# https://cryptography.io/en/latest/_modules/cryptography/x509/base/#Certificate.public_key
			cert_key = rsa.generate_private_key(
				public_exponent=65537, key_size=2048, backend=default_backend()
			)

			builder = x509.CertificateBuilder(
				subject_name=old_cert.subject, 
				issuer_name=self.ca_cert.subject,
				public_key=cert_key.public_key(),
				serial_number=old_cert.serial_number,
				not_valid_before=old_cert.not_valid_before,
				not_valid_after=old_cert.not_valid_after,
			)
			# TODO: add extensions as well maybe
			#for x in old_cert.extensions:
			#	print(type(x))
			#	builder.add_extension(x, x.critical)

			new_cert_obj = builder.sign(self.ca_key, hashes.SHA256() ,default_backend())

			new_cert = new_cert_obj.public_bytes(encoding=serialization.Encoding.PEM)
			new_key = cert_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption(),
			)

			return new_cert, new_key, None
		except Exception as e:
			logger.exception('resign_certificate')
			return None, None, e
	
	async def get_cert_by_host(self, hostname, port = 443, ssl_ctx = None):
		try:
			
			certfile, keyfile = self.load_from_cache(hostname=hostname)
			if certfile is not None:
				logger.debug('Cache hit for %s' % hostname)
				return certfile, keyfile, None

			cert, err = await CertManager.fetch_remote_cert(hostname, port, ssl_ctx=ssl_ctx)
			if err is not None:
				raise err

			certfile, keyfile = self.load_from_cache(cert_der_data=cert)
			if certfile is not None:
				logger.debug('Cache hit for %s' % hostname)
				return certfile, keyfile, None
			logger.debug('Cache miss for %s' % hostname)


			new_cert, new_key, err = self.resign_certificate(cert)
			if err is not None:
				raise err
			
			certfile, keyfile = self.store_to_cache(new_cert, new_key)

			return certfile, keyfile, None

		except Exception as e:
			logger.exception('get_cert_by_host')
			return None, None, e

	@staticmethod
	async def fetch_remote_cert(hostname, port = 443, ssl_ctx = None, binary_form = True):
		writer = None
		try:
			if ssl_ctx is None:
				ssl_ctx = ssl.create_default_context()
			_, writer = await asyncio.open_connection(host=hostname, port=port, ssl=ssl_ctx, server_hostname = hostname)
			ssl_obj = writer.get_extra_info('ssl_object')
			cert = ssl_obj.getpeercert(binary_form=binary_form)
			return cert, None

		except Exception as e:
			logger.exception('fetch_remote_cert')
			return None, e
		
		finally:
			if writer is not None:
				writer.close()

	@staticmethod
	def generate_ca(cn = 'asysocks', on = '', ou = '', key_exp = 65537, key_size = 2048):
		try:
			logger.debug('Generating initial CA certificate')
			ca_cert = None
			ca_key = None

			one_day = datetime.timedelta(1, 0, 0)
			one_year = datetime.timedelta(365, 0, 0)
			private_key = rsa.generate_private_key(
				public_exponent=key_exp,
				key_size=key_size,
				backend=default_backend()
			)
			public_key = private_key.public_key()
			builder = x509.CertificateBuilder()
			builder = builder.subject_name(x509.Name([
				x509.NameAttribute(NameOID.COMMON_NAME, cn),
				x509.NameAttribute(NameOID.ORGANIZATION_NAME, on),
				x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
			]))
			builder = builder.issuer_name(x509.Name([
				x509.NameAttribute(NameOID.COMMON_NAME, cn),
			]))
			builder = builder.not_valid_before(datetime.datetime.today() - one_day)
			builder = builder.not_valid_after(datetime.datetime.today() + one_year)
			builder = builder.serial_number(int(uuid.uuid4()))
			builder = builder.public_key(public_key)
			builder = builder.add_extension(
				x509.BasicConstraints(ca=True, path_length=None), critical=True,
			)
			certificate = builder.sign(
				private_key=private_key, algorithm=hashes.SHA256(),
				backend=default_backend()
			)

			ca_cert = certificate.public_bytes(
				encoding=serialization.Encoding.PEM,
			)

			ca_key = private_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption()
			)

			return ca_cert, ca_key, None
		except Exception as e:
			logger.exception('generate_ca')
			return None, None, e


async def amain():
	cert, err = await CertManager.fetch_remote_cert('444.hu')
	if err is not None:
		print(err)
		return
	
	print(cert)

	cm = CertManager()
	#a = cm.resign_certificate(cert)
	#print(a)
	while True:
		certfile, keyfile, err = await cm.get_cert_by_host('444.hu')
		if err is not None:
			print(err)
			return


def main():
	logger.setLevel(1)
	asyncio.run(amain())

if __name__ == '__main__':
	main()
	
