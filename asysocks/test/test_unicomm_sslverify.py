import os
import ssl

from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.common.unissl import UniSSL

CERT = os.path.join(os.path.dirname(__file__), 'cert.pem')


def test_client_verify_enforced():
	target = UniTarget('127.0.0.1', 636, UniProto.CLIENT_SSL_TCP, ssl_ctx=UniSSL(cacert=CERT, verify=True))
	ctx = target.get_ssl_context()

	assert ctx.verify_mode == ssl.CERT_REQUIRED
	assert ctx.check_hostname is True


def test_client_noverify_default():
	target = UniTarget('127.0.0.1', 636, UniProto.CLIENT_SSL_TCP)
	ctx = target.get_ssl_context()

	assert ctx.verify_mode == ssl.CERT_NONE
	assert ctx.check_hostname is False
