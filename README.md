![Supported Python versions](https://img.shields.io/badge/python-3.7+-blue.svg) [![Twitter](https://img.shields.io/twitter/follow/skelsec?label=skelsec&style=social)](https://twitter.com/intent/follow?screen_name=skelsec)

:triangular_flag_on_post: This is the public repository of aardwolf, for latest version and updates please consider supporting us through https://porchetta.industries/

# asysocks
Asynchronous Socks5 / Socks4 / HTTP proxy client and server library in pure python.

## :triangular_flag_on_post: Sponsors

If you want to sponsors this project and have the latest updates on this project, latest issues fixed, latest features, please support us on https://porchetta.industries/

## Official Discord Channel

Come hang out on Discord!

[![Porchetta Industries](https://discordapp.com/api/guilds/736724457258745996/widget.png?style=banner3)](https://discord.gg/ycGXUxy)

## what is?
The primary goal of this project to act as a universal proxy clinet/server library which you can use in your projects.  
Secondary goal is to have simple command-line tools to interact with socks proxyies or to start one yourself. See [tools](https://github.com/skelsec/asysocks#tools)  

## how can I use this in my code?
This library has three main components, [client](https://github.com/skelsec/asysocks#client) , [server](https://github.com/skelsec/asysocks#server), [security](https://github.com/skelsec/asysocks#security)

### client
The proxy client code is implemented in the `SOCKSClient` class which can be used to set up a connection to a target `host:port` via `HTTP` / `SCOSK4` / `SOCKS5` proxy protocols. It has two modes of operation: `LISTENER` and `QUEUE`

#### listener
This mode helps proxy-unaware applications to use proxies when you can set the destination `host:port` and can't use `proxychains` and alike.
It will create a TCP socket server on your localhost and each incoming client will be dispatched to the destination server via the specified proxy server.  

#### queue
This mode can be used in your scripts to support proxies. The way it works is that you will not get a direct socket rather you can delegate two `asyncio.Queue` classes (one for data in, one for data out)

### server
The proxy server is implemented in the `SOCKSServer` class. It supports `HTTP` / `SCOSK4` / `SOCKS5` protocols all on the same port. The server has basic paramteres most importantly the `listen_ip` and `listen_port` .
It also comes with a clever way to deal with intercepting traffic, see the `ProxyMonitor` class and the server's `monitor_dispatch_q` variable.

### security
TBD

## tools
These are built-in examples showing the capabilities of the library and to be used as code snipplets on setting up classes.
### asysockstunnel
Creates a listening server on localhost and tunnels all incoming connections to a pre-specified destination via a pre-defined proxy server.
### asysockssec
SOCKS4/SOCKS5 server security tester
### asysocksbrute
SOCKS5 authentication bruteforcer.
### asysocksportscan
Quick port scaning via SOCKS4/SOCKS5/HTTP proxies
### asysocksproxy
SOCKS4/SOCKS5/HTTP proxy server. Supports basic monitoring of traffic flow.

## Known issues/limitations
The biggest limitation at the moment is the lack of SSL support on server side intercepting and the same issue exists on the client side when dealing with delegated queues. Reason is that I still can't find a way to wrap arbitarary data in/out streams with python's built-in `ssl` module. Hope this will change in the future.

For more issues see [Issues](https://github.com/skelsec/asysocks/issues)
