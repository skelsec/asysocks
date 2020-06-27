
from asysocks.common.constants import SocksServerVersion, SocksProtocol


class SocksTarget:
    def __init__(self):
        self.version = None
        self.server_ip = None
        self.server_port = None
        self.is_bind = False
        self.proto = SocksProtocol.TCP
        self.timeout = 10 #used to create the connection
        self.buffer_size = 4096
        
        self.endpoint_ip = None
        self.endpoint_port = None
        self.endpoint_timeout = None #used after the connection is made
        self.userid = None

    def __repr__(self):
        return str(self.__dict__)

    def __str__(self):
        return repr(self)