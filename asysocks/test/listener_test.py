
import ipaddress
import logging
import asyncio
from asysocks.common.target import SocksTarget
from asysocks.common.comms  import SocksLitenerComms
from asysocks.common.constants import *
from asysocks.client import SOCKSClient
from asysocks import logger

logging.basicConfig(level=2)
logger.setLevel(logging.DEBUG)

async def main():
    target = SocksTarget()
    target.version = SocksServerVersion.SOCKS4
    target.server_ip = '127.0.0.1'
    target.server_port = 9050
    target.is_bind = False
    target.proto = SocksProtocol.TCP
    target.timeout = 10
    target.buffer_size = 4096
    target.endpoint_ip = ipaddress.ip_address('216.239.32.117')
    target.endpoint_port = 80

    comms = SocksLitenerComms('127.0.0.1', 9999)

    client = SOCKSClient(comms, target)
    await client.run()
    print('DONE!')


if __name__ == '__main__':
    asyncio.run(main())