
from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.common.packetizers import StreamPacketizer
from asysocks.unicomm.server import UniServer
from hashlib import sha1
from base64 import b64encode
import asyncio
import traceback
import struct

# https://github.com/Pithikos/python-websocket-server/

'''
+-+-+-+-+-------+-+-------------+-------------------------------+
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
'''

FIN    = 0x80
OPCODE = 0x0f
MASKED = 0x80
PAYLOAD_LEN = 0x7f
PAYLOAD_LEN_EXT16 = 0x7e
PAYLOAD_LEN_EXT64 = 0x7f

OPCODE_CONTINUATION = 0x0
OPCODE_TEXT         = 0x1
OPCODE_BINARY       = 0x2
OPCODE_CLOSE_CONN   = 0x8
OPCODE_PING         = 0x9
OPCODE_PONG         = 0xA

CLOSE_STATUS_NORMAL = 1000
DEFAULT_CLOSE_REASON = bytes('', encoding='utf-8')




class WebSocketServer:
    def __init__(self, client_handler, host, port, ssl_ctx = None, proxies = None):
        self.client_handler = client_handler
        self.host = host
        self.port = port
        self.ssl_ctx = ssl_ctx
        self.proxies = proxies
    
        self.clients = []
        self.id_counter = 0
        self.__main_task = None
        self.started_evt = asyncio.Event()

    async def __aenter__(self):
        self.__main_task = asyncio.create_task(self.serve())
        await asyncio.sleep(1)
        return self
    
    async def __aexit__(self, exc_type, exc, tb):
        await self.terminate()

    async def terminate(self):
        for client in self.clients:
            await client.terminate()
        self.clients = []
    
    async def __handle_connection(self, connection):
        client_id = self.id_counter
        self.id_counter += 1
        #print('Server: New client connected with id %s' % client_id)
        client = WebSocketClientHandler(client_id, self, connection, self.client_handler)
        self.clients.append(client)
        await client.run()
        self.clients.remove(client)

    
    async def serve(self):
        try:
            target = UniTarget(self.host, self.port, UniProto.SERVER_TCP, proxies=self.proxies)
            packetizer = StreamPacketizer()

            server = UniServer(target, packetizer)
            async for connection in server.serve():
                x = asyncio.create_task(self.__handle_connection(connection))

        except Exception as e:
            traceback.print_exc()

class WebSocketClientHandler:
    def __init__(self, client_id, server, connection, client_handler):
        self.client_id = client_id
        self.server = server
        self.connection = connection
        self.client_handler = client_handler
        self.incoming_buffer = asyncio.Queue()
    
    @staticmethod
    def make_handshake_response(key):
        return \
          'HTTP/1.1 101 Switching Protocols\r\n'\
          'Upgrade: websocket\r\n'              \
          'Connection: Upgrade\r\n'             \
          'Sec-WebSocket-Accept: %s\r\n'        \
          '\r\n' % WebSocketClientHandler.calculate_response_key(key)
    
    @staticmethod
    def calculate_response_key(key):
        GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
        hash = sha1(key.encode() + GUID.encode())
        response_key = b64encode(hash.digest()).strip()
        return response_key.decode('ASCII')

    async def __read_http_headers(self):
        headers = {}
        # first line should be HTTP GET
        http_raw = await self.connection.packetizer.readuntil(b'\r\n')
        http_get = http_raw.decode().strip()
        if http_get.upper().startswith('GET') is False:
            raise Exception('Invalid HTTP request: %s' % http_get)
        # remaining should be headers
        while True:
            http_raw = await self.connection.packetizer.readuntil(b'\r\n')
            header = http_raw.decode().strip()
            if not header:
                break
            head, value = header.split(':', 1)
            headers[head.lower().strip()] = value.strip()
        return headers
    
    async def handshake(self):
        try:
            headers = await self.__read_http_headers()

            if 'upgrade' not in headers:
                raise Exception('Client tried to connect but was missing an upgrade header')
            if headers['upgrade'].lower() != 'websocket':
                raise Exception('Client tried to connect but was missing a key')

            if 'sec-websocket-key' not in headers:
                raise Exception('Client tried to connect but was missing a key')

            key = headers['sec-websocket-key']        
            response = WebSocketClientHandler.make_handshake_response(key)
            await self.connection.write(response.encode())
        except Exception as e:
            traceback.print_exc()
    
    async def __recv_internal(self):
        try:
            while True:
                b1, b2 = 0, 0
                res = await self.connection.packetizer.readexactly(2)
                b1 = res[0]
                b2 = res[1]

                fin    = b1 & FIN
                opcode = b1 & OPCODE
                masked = b2 & MASKED
                payload_length = b2 & PAYLOAD_LEN

                if opcode == OPCODE_CLOSE_CONN:
                    raise Exception("Client asked to close connection.")
                
                if not masked:
                    raise Exception("Client must always be masked.")
                
                if opcode == OPCODE_CONTINUATION:
                    raise Exception("Continuation frames are not supported.")

                if payload_length in [126, 127]:
                    payload_length_raw = await self.connection.packetizer.readexactly(2 if payload_length == 126 else 8)
                    payload_length = int.from_bytes(payload_length_raw, byteorder='big')

                masks = await self.connection.packetizer.readexactly(4)
                message_bytes = bytearray()

                raw = await self.connection.packetizer.readexactly(payload_length)
                for c in raw:
                    c ^= masks[len(message_bytes) % 4]
                    message_bytes.append(c)
                yield opcode, bytes(message_bytes)
        
        except Exception as e:
            traceback.print_exc()
            yield None, None

    async def send_pong(self, data):
        if isinstance(data, str) is True:
            data = data.encode('utf-8')
        await self.__send_internal(OPCODE_PONG, data)

    async def send_ping(self, data):
        if isinstance(data, str) is True:
            data = data.encode('utf-8')
        await self.__send_internal(OPCODE_PING, data)

    async def start_recv(self):
        async for opcode, data in self.__recv_internal():
            if opcode is None:
                break
            #print('Received opcode: %s' % opcode)
            #print('Received data: %s' % data)
            
            if opcode == OPCODE_TEXT:
                self.incoming_buffer.put_nowait(data.decode('utf-8'))
            elif opcode == OPCODE_BINARY:
                self.incoming_buffer.put_nowait(data)
            elif opcode == OPCODE_PING:
                await self.send_pong(data)
            elif opcode == OPCODE_PONG:
                print('Received pong')
            elif opcode == OPCODE_CLOSE_CONN:
                break
            else:
                print('Unknown opcode %s' % opcode)
            
        #print('Client disconnected')

    async def __send_internal(self, opcode, data:bytes):
        header  = bytearray()
        payload_length = len(data)

        # Normal payload
        if payload_length <= 125:
            header.append(FIN | opcode)
            header.append(payload_length)

        # Extended payload
        elif payload_length >= 126 and payload_length <= 65535:
            header.append(FIN | opcode)
            header.append(PAYLOAD_LEN_EXT16)
            header.extend(struct.pack(">H", payload_length))

        # Huge extended payload
        elif payload_length < 18446744073709551616:
            header.append(FIN | opcode)
            header.append(PAYLOAD_LEN_EXT64)
            header.extend(struct.pack(">Q", payload_length))

        else:
            raise Exception("Message is too big. Consider breaking it into chunks.")
        
        await self.connection.write(header + data)
    
    async def send(self, data):
        if isinstance(data, str) is True:
            opcode = OPCODE_TEXT
            await self.__send_internal(opcode, data.encode('utf-8'))
        else:
            opcode = OPCODE_BINARY
            await self.__send_internal(opcode, data)
            
    async def run(self):
        x = asyncio.create_task(self.connection.stream())
        await self.handshake()
        x = asyncio.create_task(self.start_recv())
        conn = WebSocketClientConnection(self)
        await self.client_handler(conn)

class WebSocketClientConnection:
    def __init__(self, clienthandler):
        self.clienthandler = clienthandler
    
    def __aiter__(self):
        return self
    
    async def __anext__(self):
        return await self.clienthandler.incoming_buffer.get()
    
    async def recv(self):
        return await self.clienthandler.incoming_buffer.get()
    
    async def send(self, data):
        await self.clienthandler.send(data)

    async def ping(self, data):
        await self.clienthandler.send_ping(data)


serve = WebSocketServer