#pragma once

#include "stream_libuv.h"
#include "stream_libuvTLS.h"

#include "kclient_server.h"
#include "kclient_socks5.h"
#include "kclient_multiplexer.h"
#include "kclient_relay.h"
#include "kclient_clientproxy.h"


NS_PROXY_CLIENT_START

class UVServer: protected EBStreamUV, public Server {
    public:
    inline UVServer(std::shared_ptr<ClientConfig> config, UNST connection):
        Server(config), EBStreamUV(connection) {assert(connection->getType() == StreamType::LIBUV);}
    inline UVServer(std::shared_ptr<ClientConfig> config, uv_tcp_t* connection):
        Server(config), EBStreamUV(connection) {}
};
class UVSocks5Auth: protected EBStreamUV, public Socks5Auth {
    public:
    inline UVSocks5Auth(Server* server, std::shared_ptr<ClientConfig> config, uv_tcp_t* connection):
        Socks5Auth(server, config), EBStreamUV(connection) {}
};
class UVMultiplexer: protected EBStreamUV, public ConnectionProxy {
    public:
    inline UVMultiplexer(Server* server, SingleServerInfo* config, uv_tcp_t* connection):
        ConnectionProxy(server, config), EBStreamUV(connection) {}
};
class UVRelay: public RelayConnection {
    public:
    inline UVRelay(Server* server, Socks5ServerAbstraction* socks5,
            const std::string& addr, uint16_t port, EBStreamAbstraction::UNST connection):
        RelayConnection(server, socks5, addr, port, connection) {assert(connection->getType() == StreamType::LIBUV);}
};
class UVClientConnection: public ClientConnection {
    public:
    inline UVClientConnection(Server* server, ProxyMultiplexerAbstraction* mgr, 
                              const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5):
        ClientConnection(server, mgr, addr, port, socks5){}
};


class UVTLSMultiplexer: protected EBStreamUVTLS, public ConnectionProxy {
    public:
        inline
            UVTLSMultiplexer(Server* server, SingleServerInfo* config, uv_tcp_t* connection):
                ConnectionProxy(server, config), EBStreamUVTLS(connection, TLSMode::ClientMode, "", "") {}
};


NS_PROXY_CLIENT_END

