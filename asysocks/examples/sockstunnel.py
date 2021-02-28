
import logging
import asyncio


from asysocks import logger
from asysocks._version import __banner__
from asysocks.client import SOCKSClient
from asysocks.common.clienturl import SocksClientURL
from asysocks.common.comms import SocksLitenerComms

def main():
	import argparse

	parser = argparse.ArgumentParser(description='Transparent TCP tunnel for SOCKS unaware clients.')
	parser.add_argument('-l', '--listen-ip', default = '127.0.0.1',  help='Listener IP address to bind to')
	parser.add_argument('-p', '--listen-port', type = int, default = 11111, help='Listener port number to bind to')
	parser.add_argument('-t', '--timeout', type = int, default = None, help='Endpoint timeout')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('dst_ip', help='IP address of the desination server')
	parser.add_argument('dst_port', type = int, help='port number of the desination service')
	parser.add_argument('proxy_connection_strings', nargs='*', help='connection string(s) decribing the socks proxy server connection properties')

	args = parser.parse_args()

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)
		

	elif args.verbose > 2:
		logger.setLevel(1)

	comms = SocksLitenerComms(args.listen_ip, args.listen_port)

	prev_url = None
	proxies = []
	for con_str in args.proxy_connection_strings[::-1]:
		url = SocksClientURL.from_url(con_str)
		if prev_url is None:
			url.endpoint_ip = args.dst_ip
			url.endpoint_port = args.dst_port
			url.endpoint_timeout = args.timeout
		else:
			prev_target = prev_url.get_target()
			url.endpoint_ip = prev_target.server_ip
			url.endpoint_port = prev_target.server_port
			url.endpoint_timeout = args.timeout

		prev_url = url
		proxies.append(url)

	proxies = proxies[::-1]
	targets = [ x.get_target() for x in proxies]
	credentials = None

	if args.verbose >=1:
		print(str(targets))

	print(__banner__)

	tunnel = ''
	for target in targets:
		tunnel += "|--->| (%s) %s:%s " % (target.version.name.upper() ,target.server_ip, target.server_port)
	
	print(tunnel)

	layout = """Connection layout
	
	CLIENT --->|
	CLIENT --->|(LISTENER) %s:%s  %s |--->| (FINAL DST) %s:%s
	CLIENT --->|
	
	""" % (args.listen_ip, args.listen_port, tunnel , args.dst_ip, args.dst_port)

	print(layout)

	client = SOCKSClient(comms, targets, credentials)

	print('Waiting for incoming connections')
	asyncio.run(client.run())
	


if __name__ == '__main__':
	main()