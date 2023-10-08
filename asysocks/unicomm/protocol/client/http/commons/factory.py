
import copy
import enum
from asyauth.common.credentials import UniCredential
from asysocks.unicomm.protocol.client.http.commons.target import HTTPTarget

class HTTPConnectionFactory:
	def __init__(self, credential:UniCredential = None, target:HTTPTarget = None ):
		self.credential = credential
		self.target = target
	
	@staticmethod
	def from_url(connection_url, proxies = None):
		target = HTTPTarget.from_url(connection_url)
		credential = UniCredential.from_url(connection_url)
		if credential.secret is None:
			credential = None
		if target.domain is None and credential is not None:
			target.domain = credential.domain
		if proxies is not None:
			target.proxies = proxies
		return HTTPConnectionFactory(credential, target)

	def get_credential(self) -> UniCredential:
		"""
		Creates a credential object
		
		:return: Credential object
		:rtype: :class:`UniCredential`
		"""
		return copy.deepcopy(self.credential)
	
	def get_target(self) -> HTTPTarget:
		"""
		Creates a target object
		
		:return: Target object
		:rtype: :class:`HTTPTarget`
		"""
		return copy.deepcopy(self.target)
	
	
	def __str__(self):
		t = '==== HTTPConnectionFactory ====\r\n'
		for k in self.__dict__:
			val = self.__dict__[k]
			if isinstance(val, enum.IntFlag):
				val = val
			elif isinstance(val, enum.Enum):
				val = val.name
			
			t += '%s: %s\r\n' % (k, str(val))
			
		return t