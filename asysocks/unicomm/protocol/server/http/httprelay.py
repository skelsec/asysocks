
import base64
import traceback
from typing import List
from asysocks.unicomm.protocol.server.http.httpserver import HTTPServerHandler

# SPNEGO is not fully implemented yet, will be useful for kerberos relaying

import h11

async def dummy_log(msg:str):
    print(msg)

class HTTPRelayHandler(HTTPServerHandler):
    def __init__(self, relay_handler, *args, is_proxy:bool = False, authtype:str='NTLM', authbody:bytes=None, successbody:bytes=None, log_callback=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.webdav_url = ''
        self.relay_handler = relay_handler
        self.gssapi = relay_handler()
        self.authtype = authtype.upper()
        if authtype not in ['NTLM', 'SPNEGO']:
            raise Exception('Unsupported auth type %s' % authtype)
        if is_proxy is True:
            self.unauthorized_reason = 'Proxy Authentication Required'
            self.authorization_key = 'Proxy-Authenticate'
            self.client_auth_key = 'Proxy-Authorization'
            self.unauthorized_status = 407
        else:
            self.unauthorized_reason = 'Unauthorized'
            self.authorization_key = 'WWW-Authenticate'
            self.client_auth_key = 'Authorization'
            self.unauthorized_status = 401
        
        if isinstance(authbody, str):
            authbody = authbody.encode()
        if isinstance(successbody, str):
            successbody = successbody.encode()
        self.authbody = authbody
        self.successbody = successbody
        self.log_callback = log_callback

    def get_auth_header(self, request):
        client_auth_key = self.client_auth_key.lower().encode('ascii')
        for header in request.headers:
            if header[0] == client_auth_key:
                return header[1]
    
    async def debug(self, *args):
        msg = [str(x) for x in args]
        msg = ' '.join(msg)
        if self.log_callback is not None:
            await self.log_callback(msg)

    async def initial_response(self):
        await self.debug('Initial response')
        try:
            status_code = 401
            headers = self.basic_headers()
            headers.append(("Connection", 'keep-alive'))
            if self.authbody is not None:
                headers.append(("Content-Type", 'text/html'))
                headers.append(("Content-Length", str(len(self.authbody))))
            headers.append((self.authorization_key, self.authtype))
            res = h11.Response(status_code=status_code, headers=headers)
            await self._wrapper.send(res)
            if self.authbody is not None:
                await self._wrapper.send(h11.Data(data=self.authbody))
            await self._wrapper.send(h11.EndOfMessage())
        except Exception as e:
            traceback.print_exc()
    
    async def send_auth_progress(self, auth_data:bytes):
        await self.debug('send_auth_progress %s' % auth_data)
        status_code = 401
        headers = self.basic_headers()
        headers.append((self.authorization_key, auth_data))
        res = h11.Response(status_code=status_code, headers=headers)
        await self._wrapper.send(res)
        await self._wrapper.send(h11.EndOfMessage())

    async def send_success(self, auth_data:bytes = None, extra_headers:List[tuple] = []):
        await self.debug('send_success %s' % auth_data)
        status_code = 200
        headers = self.basic_headers()
        headers.extend(extra_headers)
        headers.append(("Content-Type", 'text/html'))
        if self.successbody is not None:
            headers.append(("Content-Length", str(len(self.successbody))))
        if auth_data is not None:
            headers.append((self.authorization_key, auth_data))
        res = h11.Response(status_code=status_code, headers=headers)
        await self._wrapper.send(res)
        if self.successbody is not None:
            await self._wrapper.send(h11.Data(data=self.successbody))
        await self._wrapper.send(h11.EndOfMessage())
    
    async def handle_options(self, request):
        extra_headers = [
            ('Access-Control-Allow-Methods', 'OPTIONS, PROPFIND, GET, PUT, DELETE, MKCOL, LOCK, UNLOCK'),
            ('Access-Control-Allow-Origin', '*'),
            ('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        ]
        await self.send_success(extra_headers=extra_headers)
    
    async def handle_propfind(self, request):
        status_code = 207
        request_target =  request.target.decode()
        request_file = request_target.split('/')[-1]
        getcontentlength = 0
        creationdate = '2016-11-12T22:00:22Z'
        content = f"""<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>{self.webdav_url}</D:href><D:propstat><D:prop><D:creationdate>{creationdate}</D:creationdate><D:displayname>{request_file}</D:displayname><D:getcontentlength>{getcontentlength}</D:getcontentlength><D:getcontenttype></D:getcontenttype><D:getetag></D:getetag><D:getlastmodified>Mon, 20 Mar 2017 00:00:22 GMT</D:getlastmodified><D:resourcetype><D:collection></D:collection></D:resourcetype><D:supportedlock></D:supportedlock><D:ishidden>0</D:ishidden></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"""

        headers = self.basic_headers()
        headers.append(("Content-Type", 'text/xml'))
        headers.append(("Content-Length", str(len(content))))
        
        res = h11.Response(status_code=status_code, headers=headers)
        await self._wrapper.send(res)
        await self._wrapper.send(h11.Data(data=content.encode()))
        await self._wrapper.send(h11.EndOfMessage())
    
    async def handle_head(self, request):
        headers = self.basic_headers()
        headers.append(("Content-Type", 'text/xml'))

        res = h11.Response(status_code=200, headers=headers)
        await self._wrapper.send(res)
        await self._wrapper.send(h11.EndOfMessage())


    async def _process_request(self, wrapper, request):
        authtype = self.authtype.encode()
        authobj = None
        # setting connection info
        self.gssapi.set_connection_info(wrapper.stream) #UniConnection
        if self.authtype == 'NTLM':
            authobj = self.gssapi.get_ntlm()
        elif self.authtype == 'SPNEGO':
            authobj = self.gssapi
        try:
            self._wrapper = wrapper
            auth_data = self.get_auth_header(request)
            await self.debug('auth_data %s' % auth_data)
            if auth_data is None:
                if request.method == b'OPTIONS':
                    await self.handle_options(request)
                    return
                elif request.method == b'PROPFIND':
                    await self.handle_propfind(request)
                    return
                elif request.method == b'HEAD':
                    await self.handle_head(request)
                    return
                await self.initial_response()
                return
            else:
                if auth_data.startswith(authtype) is True:
                    auth_data = base64.b64decode(auth_data[len(authtype)+1:])
                    res, to_continue, err = await authobj.authenticate_relay_server(auth_data)
                    if err is not None:
                        raise err

                    if to_continue is True and res is not None:
                        await self.send_auth_progress(b'%s %s' % (authtype, base64.b64encode(res)))
                        return
                    
                    res_data = None
                    if res is not None:
                        res_data = b'%s %s' % (authtype, base64.b64encode(res))
                    await self.send_success(res_data)
                else:
                    raise Exception('Authdata doesnt seem to be NTLM! %s' % auth_data)
        except Exception as e:
            traceback.print_exc()
            raise e
        