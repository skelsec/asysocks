
import asyncio
import logging
import ssl


from asysocks.server import SOCKSServer, srvlogger, ProxyMonitorSSL
from asysocks._version import __banner__

async def amain():
	try:
		import argparse
		parser = argparse.ArgumentParser(description='Universal proxy server (SOCKS4/5 and HTTP proxy')
		parser.add_argument('--listen-ip', default = '127.0.0.1', help='Listen IP')
		parser.add_argument('--listen-port', type = int, default = 1080, help='Listen port')
		parser.add_argument('--cert', help='SSL certificate file')
		parser.add_argument('--key', help='SSL key file')
		parser.add_argument('--client-timeout', type=int, default=10, help='How much time to wait ftill the client finishes initial handshake')
		parser.add_argument('--buffer-size', type=int, default=10240, help='Proxy buffer size')
		parser.add_argument('-m', '--monitor', action='store_true', help='Monitor mode.')
		parser.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity')
		parser.add_argument('-s', '--silent', action='store_true', help = 'dont print banner')

		args = parser.parse_args()

		####
		####
		fake_cert = 'asysocks/test/cert.pem'
		fake_key = 'asysocks/test/key.pem'
		fake_pass = 'testcert'

		####


		if args.silent is False:
			print(__banner__)

		if args.verbose >=1:
			srvlogger.setLevel(logging.DEBUG)

		ssl_ctx = None 
		client_timeout = args.client_timeout
		buffer_size = args.buffer_size
		supported_protocols = ['SOCKS4','SOCKS5', 'HTTP']
		monitor_dispatch_q = None

		if args.cert is not None:
			ssl_ctx = ssl.SSLContext()
			ssl_ctx.load_cert_chain(args.cert, keyfile=args.key)

		
		if args.monitor is True:
			monitor_dispatch_q = asyncio.Queue()
		
		server = SOCKSServer(
			args.listen_ip, 
			args.listen_port, 
			ssl_ctx, 
			client_timeout = client_timeout, 
			buffer_size = buffer_size, 
			supported_protocols = supported_protocols, 
			monitor_dispatch_q=monitor_dispatch_q
		)

		if args.silent is False:
			print('Proxy server is up and running on %s:%s %s' % (args.listen_ip, args.listen_port, '' if ssl_ctx is None else '(SSL)'))
		
		if monitor_dispatch_q is None:
			await server.run()
		else:
			server_task = asyncio.create_task(server.run())
			while True:
				#each connection will give a monitor class
				monitor = await monitor_dispatch_q.get()
				if monitor.dst_port == 443:
					client_ssl_ctx = ssl.create_default_context()
					client_ssl_ctx.check_hostname = False
					client_ssl_ctx.verify_mode = ssl.CERT_NONE
					
					print(client_ssl_ctx.verify_mode)
					client_ssl_ctx.load_cert_chain(fake_cert, fake_key, password=fake_pass)
					
					destination_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
					destination_ssl_ctx.check_hostname = False
					destination_ssl_ctx.verify_mode = ssl.CERT_NONE
					destination_ssl_ctx.set_ciphers('DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:TLS_AES_128_GCM_SHA256')
					ssl_monitor = ProxyMonitorSSL(monitor, client_ssl_ctx = client_ssl_ctx, destination_ssl_ctx = destination_ssl_ctx)
					asyncio.create_task(ssl_monitor.intercept())
				else:
					asyncio.create_task(monitor.just_log())

			server_task.cancel()

	except Exception as e:
		print(e)

def main():
	asyncio.run(amain())

if __name__ == '__main__':
	main()