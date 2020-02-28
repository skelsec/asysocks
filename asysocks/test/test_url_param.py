import logging
from asysocks.common.clienturl  import SocksClientURL
from asysocks import logger

logging.basicConfig(level=2)
logger.setLevel(logging.DEBUG)


def main():
    url_1 = 'smb://10.10.10.2/?timeout=10&dc=10.10.10.2&proxytype=socks5&proxyserver=127.0.0.1&proxyuser=admin&proxypass=alma&dc=10.10.10.2&dns=8.8.8.8'
    cu = SocksClientURL.from_params(url_1)

    target = cu.get_target()
    print(repr(target))

if __name__ == '__main__':
    main()