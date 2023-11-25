import base64
from hashlib import sha256

from asysocks.unicomm.protocol.client.http import logger
from asysocks.unicomm.common.target import UniProto
from asysocks.unicomm.protocol.client.http.requestmgr import RequestManager

from asyauth.common.winapi.constants import ISC_REQ
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.kerberos import KerberosCredential
from asyauth.common.credentials.spnego import SPNEGOCredential
from asyauth.common.credentials.credssp import CREDSSPCredential


class HTTPAuthManager:
	def __init__(self, session, credential):
		self.session = session
		self.status = 'start'
		self.authobj = credential.build_context()
		self.credential = credential
	
	async def authenticate(self, requestmanager):
		pass

	@staticmethod
	def from_credential(session, credential, auth_type:str = 'auto'):
		auth_type = auth_type.lower()
		if auth_type == 'auto':
			if isinstance(credential, (SPNEGOCredential)) is True:
				return HTTPAuthManagerNegotiate(session, credential)
			elif isinstance(credential, (NTLMCredential, KerberosCredential)) is True:
				credential = SPNEGOCredential([credential])
				return HTTPAuthManagerNegotiate(session, credential)
			else:
				raise Exception('No supported auth type found!')
		elif auth_type == 'spnego':
			if isinstance(credential, (SPNEGOCredential)) is True:
				return HTTPAuthManagerNegotiate(session, credential)
			elif isinstance(credential, (NTLMCredential, KerberosCredential)) is True:
				credential = SPNEGOCredential([credential])
				return HTTPAuthManagerNegotiate(session, credential)
			else:
				raise Exception('Credential type %s cannot be used for SPNEGO authentication!' % credential.__class__.__name__)
		elif auth_type == 'credssp':
			if isinstance(credential, (CREDSSPCredential)) is True:
				return HTTPAuthManagerCredSSP(session, credential)
			elif isinstance(credential, (NTLMCredential, KerberosCredential)) is True:
				credential = CREDSSPCredential([credential])
				return HTTPAuthManagerCredSSP(session, credential)
		else:
			raise Exception('Unsupported auth type! Authtype: %s Credential: %s' % (auth_type, credential.__class__.__name__))


class HTTPAuthManagerCredSSP(HTTPAuthManager):
	def __init__(self, session, credential:CREDSSPCredential):
		HTTPAuthManager.__init__(self, session, credential)
		self.auth_steps = False
		self.cb_data = None
	
	async def authenticate(self, requestmanager):
		self.status = 'progress'
		authreply = None
		domain = 'UNKNOWN'
		for cred in self.credential.credentials:
			domain = cred.domain
			break

		while True:
			flags = ISC_REQ.CONNECTION|ISC_REQ.CONFIDENTIALITY|ISC_REQ.INTEGRITY
			target_spn = 'HTTP/%s@%s' % (requestmanager.transport.target.get_hostname_or_ip(), domain)
			authdata, to_continue, err = await self.authobj.authenticate(authreply, spn=target_spn, flags=flags) #, cb_data = self.cb_data
			if err is not None:
				raise err
			
			if to_continue is False and response.status == 200:
				return response
			
			auth_header = 'CredSSP '+ base64.b64encode(authdata).decode()
			newheaders = []
			newheaders.append(('Authorization', auth_header))
			for entry in requestmanager.headers:
				newheaders.append(entry) 
			
			async with RequestManager(self.session, requestmanager.url, requestmanager.req_type, headers=newheaders, data=requestmanager.data, need_length=requestmanager.need_length, transport=requestmanager.transport) as response:
				if to_continue is False and response.status != 200:
					raise Exception('Authentication failed! %s' % response.status)
				await response.read() #consuming all data is mandatory here!
				if response.transport.connection is not None and response.transport.can_reuse is True:
					self.transport = response.transport

				response_auth_header = response.getheaders('www-authenticate')
				if response_auth_header is None or len(response_auth_header) == 0:
					if to_continue is False and response.status == 200:
						return response
					raise Exception('Authentication failed! No www-authenticate header found!')
				for rauthh in response_auth_header:
					if rauthh.startswith('CredSSP'):
						response_auth_header = rauthh
						break
				else:
					if to_continue is False and response.status == 200:
						return response
					raise Exception('Authentication failed! No CredSSP header found!')
				

				response_header_data_b64 = response_auth_header.replace('CredSSP ', '').strip().encode()
				if response_header_data_b64 == b'':
					if to_continue is False and response.status == 200:
						return response
					raise Exception('Authentication failed! Empty CredSSP header found!')
				
				authreply = base64.b64decode(response_header_data_b64)
			
			if to_continue is False and response.status == 200:
				return response
			
class HTTPAuthManagerNegotiate(HTTPAuthManager):
	def __init__(self, session, credential:SPNEGOCredential):
		HTTPAuthManager.__init__(self, session, credential)
		self.auth_steps = False
		self.cb_data = None
	
	async def authenticate(self, requestmanager):
		self.status = 'progress'
		authreply = None
		domain = 'UNKNOWN'
		for cred in self.credential.credentials:
			domain = cred.domain
			break
		while True:
			flags = ISC_REQ.CONNECTION|ISC_REQ.CONFIDENTIALITY|ISC_REQ.INTEGRITY|ISC_REQ.USE_DCE_STYLE|ISC_REQ.MUTUAL_AUTH
			if requestmanager.transport.target.protocol == UniProto.CLIENT_SSL_TCP:
				if self.cb_data is None:
					certdata = requestmanager.transport.connection.get_peer_certificate()
					if certdata is not None:
						self.cb_data = b'tls-server-end-point:' + sha256(certdata).digest()

			#	flags = ISC_REQ.CONNECTION
			target_spn = 'HTTP/%s@%s' % (requestmanager.transport.target.get_hostname_or_ip(), domain)
			authdata, to_continue, err = await self.authobj.authenticate(authreply, spn=target_spn, flags=flags, cb_data = self.cb_data) #, 
			if err is not None:
				raise err
			
			if to_continue is False and response.status == 200:
				logger.debug('Authentication successful!')
				return response
			
			auth_header = 'Negotiate '+ base64.b64encode(authdata).decode()
			newheaders = []
			newheaders.append(('Authorization', auth_header))
			for entry in requestmanager.headers:
				newheaders.append(entry) 
			
			logger.debug('Updated Headers: %s' % newheaders)
			async with RequestManager(self.session, requestmanager.url, requestmanager.req_type, headers=newheaders, data=requestmanager.data, need_length=requestmanager.need_length, transport=requestmanager.transport) as response:
				logger.debug('Response Status: %s' % response.status )
				logger.debug('Response Headers: %s' % response.headers)
				
				if to_continue is False and response.status != 200:
					raise Exception('Authentication failed! %s' % response.status)
				await response.read() #consuming all data is mandatory here!
				if response.transport.connection is not None and response.transport.can_reuse is True:
					self.transport = response.transport
				
				authreply = response.getheaders('www-authenticate')[0].replace('Negotiate ', '').strip().encode()
				authreply = base64.b64decode(authreply)
			
			if to_continue is False and response.status == 200:
				logger.debug('Authentication successful!')
				return response
