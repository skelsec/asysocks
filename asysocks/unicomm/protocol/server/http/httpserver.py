
from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.common.connection import UniConnection
from asysocks.unicomm.common.packetizers import StreamPacketizer, Packetizer
from asysocks.unicomm.server import UniServer
import asyncio
import traceback
from itertools import count
import datetime
import email.utils
import h11

class AsysocksHTTPWrapper:
    _next_id = count()

    def __init__(self, client_id, stream:UniConnection, log_callback=None):
        self.log_callback = log_callback
        self.client_id = client_id
        self.MAX_RECV = 2**16
        self.stream = stream
        self.conn = h11.Connection(h11.SERVER)
        # Our Server: header
        self.ident = " ".join(
            [f"h11-example-asysocks-server/{h11.__version__}", h11.PRODUCT_ID]
        ).encode("ascii")
        # A unique id for this connection, to include in debugging output
        # (useful for understanding what's going on if there are multiple
        # simultaneous clients).
        self._obj_id = next(AsysocksHTTPWrapper._next_id)
        
    async def debug(self, *args):
        msg = [str(x) for x in args]
        msg = ' '.join(msg)
        if self.log_callback is not None:
            await self.log_callback(msg)

    async def send(self, event):
        # The code below doesn't send ConnectionClosed, so we don't bother
        # handling it here either -- it would require that we do something
        # appropriate when 'data' is None.
        assert type(event) is not h11.ConnectionClosed
        data = self.conn.send(event)
        try:
            await self.stream.write(data)
        except BaseException:
            # If send_all raises an exception (especially trio.Cancelled),
            # we have no choice but to give it up.
            self.conn.send_failed()
            raise

    async def _read_from_peer(self):
        if self.conn.they_are_waiting_for_100_continue:
            await self.debug("Sending 100 Continue")
            go_ahead = h11.InformationalResponse(
                status_code=100, headers=self.basic_headers()
            )
            await self.send(go_ahead)
        try:
            await self.debug('[%s] Reading from peer...' % self.client_id)
            #data = await self.stream.packetizer.read(self.MAX_RECV)
            data = await self.stream.read_one()
            await self.debug('[%s] DATA: %s' % (self.client_id, data))
        except Exception as exc:
            await self.debug('Error reading from peer:', exc)
            # They've stopped listening. Not much we can do about it here.
            data = b""
        self.conn.receive_data(data)

    async def next_event(self):
        while True:
            event = self.conn.next_event()
            await self.debug('[%s] Event: %s' % (self.client_id, event))
            if event is h11.NEED_DATA:
                await self._read_from_peer()
                continue
            return event

    async def shutdown_and_clean_up(self):
        try:
            await self.stream.close()
        except Exception as exc:
            return
        
        #maybe read some more?

    def basic_headers(self):
        # HTTP requires these headers in all responses (client would do
        # something different here)
        return [
            ("Date", self.format_date_time().encode("ascii")),
            ("Server", self.ident),
        ]
    
    def format_date_time(self, dt=None):
        """Generate a RFC 7231 / RFC 9110 IMF-fixdate string"""
        if dt is None:
            dt = datetime.datetime.now(datetime.timezone.utc)
        return email.utils.format_datetime(dt, usegmt=True)

class HTTPServerHandler:
    def __init__(self):
        self._wrapper:AsysocksHTTPWrapper = None
        self.ident = " ".join(
            [f"h11-example-asysocks-server/{h11.__version__}", h11.PRODUCT_ID]
        ).encode("ascii")

    @staticmethod
    def format_date_time(dt=None):
        """Generate a RFC 7231 / RFC 9110 IMF-fixdate string"""
        if dt is None:
            dt = datetime.datetime.now(datetime.timezone.utc)
        return email.utils.format_datetime(dt, usegmt=True)
    
    def basic_headers(self):
        # HTTP requires these headers in all responses (client would do
        # something different here)
        return [
            ("Date", HTTPServerHandler.format_date_time().encode("ascii")),
            ("Server", self.ident),
        ]

    async def _process_request(self, wrapper:AsysocksHTTPWrapper, request:h11.Event):
        self._wrapper = wrapper
        method = request.method.decode("ascii")
        func = getattr(self, f"do_{method}", None)
        if func is None:
            response = h11.Response(status_code=405, headers=wrapper.basic_headers())
            response.body = b"Method Not Allowed"
            return await wrapper.send(response)
        response = await func(request)
        await wrapper.send(response)

    async def do_GET(self, event):
        body = "Hello, world!".encode("ascii")
        status_code = 200
        headers = self.basic_headers()
        headers.append(("Content-Type", 'text/html'))
        headers.append(("Content-Length", str(len(body))))
        res = h11.Response(status_code=status_code, headers=headers)
        await self._wrapper.send(res)
        await self._wrapper.send(h11.Data(data=body))
        await self._wrapper.send(h11.EndOfMessage())


class HTTPServer:
    def __init__(self, client_handler:HTTPServerHandler, target:UniTarget, ssl_ctx = None, log_callback=None):
        self.log_callback = log_callback
        self.target = target
        self.client_handler = client_handler
        self.ssl_ctx = ssl_ctx

        self.clients = []
        self.id_counter = 0
        self.__main_task = None
        self.started_evt = asyncio.Event()

    async def debug(self, *args):
        msg = [str(x) for x in args]
        msg = ' '.join(msg)
        if self.log_callback is not None:
            await self.log_callback(msg)

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
        try:
            #x = asyncio.create_task(connection.stream())
            client_id = self.id_counter
            self.id_counter += 1
            wrapper = AsysocksHTTPWrapper(client_id, connection)
            handler = self.client_handler()
            await self.debug('Server: New client connected with id %s' % client_id)
            while True:
                if wrapper.conn.states == {h11.CLIENT: h11.CLOSED, h11.SERVER: h11.CLOSED}:
                    break

                if wrapper.conn.states[h11.CLIENT] == h11.MUST_CLOSE:
                    break

                if wrapper.conn.states[h11.SERVER] == h11.MUST_CLOSE:
                    break

                if wrapper.conn.states == {h11.CLIENT: h11.DONE, h11.SERVER: h11.DONE}:
                    wrapper.conn.start_next_cycle()
                    continue

                if not (wrapper.conn.states == {h11.CLIENT: h11.IDLE, h11.SERVER: h11.IDLE}):
                    if not (wrapper.conn.states == {h11.CLIENT: h11.SEND_BODY, h11.SERVER: h11.DONE}):
                        await self.debug('[%s] Server: Connection state not idle' % client_id)
                        await self.debug(wrapper.conn.states)
                        break

                try:
                    await self.debug("Server main loop waiting for request")
                    event = await wrapper.next_event()
                    if event is None:
                        break
                    await self.debug("Server main loop got event:", event)
                    if type(event) is h11.Request:
                        try:
                            await handler._process_request(wrapper, event)
                        except Exception as exc:
                            break
                        continue
                    if type(event) is h11.ConnectionClosed:
                        break
                    await self.debug('[%s] Server: unknown event type %s' % (client_id, type(event)))
                except Exception as exc:
                    await self.debug(f"Error during response handler: {exc!r}")
                    break
        except Exception as e:
            traceback.print_exc()
            await connection.close()

    
    async def serve(self):
        try:
            packetizer = Packetizer()
            server = UniServer(self.target, packetizer)
            async for connection in server.serve():
                x = asyncio.create_task(self.__handle_connection(connection))

        except Exception as e:
            traceback.print_exc()

async def relaytest():
    from asyauth.protocols.spnego.relay.native import spnegorelay_ntlm_factory
    from asyauth.protocols.ntlm.relay.native import NTLMRelaySettings, ntlmrelay_factory
    from asysocks.unicomm.protocol.server.http.httprelay import HTTPRelayHandler

    async def read_q(queue):
        while True:
            item = await queue.get()
            print(item)

    async def dummy_log(msg:str):
        print(msg)

    def ntlm_settings_factory():
        ntlm_settings = NTLMRelaySettings()
        ntlm_settings.log_callback = dummy_log
        ntlm_settings.timeout = 5
        #ntlm_settings.force_signdisable = False
        #ntlm_settings.dropmic = False
        #ntlm_settings.dropmic2 = False
        #ntlm_settings.modify_negotiate_cb = None
        #ntlm_settings.modify_challenge_cb = None
        #ntlm_settings.modify_authenticate_cb = None
        return ntlm_settings

    target = UniTarget('0.0.0.0', 80, UniProto.SERVER_TCP)
    auth_relay_queue = asyncio.Queue()
    x = asyncio.create_task(read_q(auth_relay_queue))
    relay_handler = lambda: spnegorelay_ntlm_factory(auth_relay_queue, lambda: ntlmrelay_factory(ntlm_settings_factory))
    server = HTTPServer(lambda: HTTPRelayHandler(relay_handler), target, log_callback=dummy_log)
    await server.serve()
    print('done')

if __name__ == '__main__':
    asyncio.run(relaytest())