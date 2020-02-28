
import ipaddress
import logging
import asyncio
from asysocks.common.target import SocksTarget
from asysocks.common.comms  import SocksQueueComms
from asysocks.common.constants import *
from asysocks.client import SOCKSClient
from asysocks import logger

logging.basicConfig(level=2)
logger.setLevel(logging.DEBUG)

async def read_q(in_queue):
    while True:
        data = await in_queue.get()
        print(data)

async def main():
    in_queue = asyncio.Queue()
    out_queue = asyncio.Queue()
    await out_queue.put(b'GET / HTTP/1.1\r\nHost: google.com\r\n\r\n')

    target = SocksTarget()
    #target.version = SocksServerVersion.SOCKS4
    target.version = SocksServerVersion.SOCKS5
    target.server_ip = '127.0.0.1'
    target.server_port = 9050
    target.is_bind = False
    target.proto = SocksProtocol.TCP
    target.timeout = 10
    target.buffer_size = 4096
    target.endpoint_ip = ipaddress.ip_address('216.239.32.117')
    target.endpoint_port = 80

    comms = SocksQueueComms(out_queue, in_queue)
    t = asyncio.create_task(read_q(in_queue))

    client = SOCKSClient(comms, target)
    await client.run()
    print('DONE!')


if __name__ == '__main__':
    asyncio.run(main())