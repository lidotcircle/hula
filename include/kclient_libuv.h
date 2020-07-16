#include "stream_libuv.hpp"

#include "kclient_server.h"
#include "kclient_socks5.h"
#include "kclient_multiplexer.h"
#include "kclient_relay.h"
#include "kclient_clientproxy.h"


NS_PROXY_CLIENT_START

class UVServer: protected EBStreamUV, public Server {
    public:
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
            const std::string& addr, uint16_t port, uv_tcp_t* connection):
        RelayConnection(server, socks5, addr, port, connection) {}
};
class UVClientConnection: protected EBStreamUV, public ClientConnection {
    public:
    inline UVClientConnection(Server* server, ProxyMultiplexerAbstraction* mgr, 
                              const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5,
                              uv_tcp_t* connection):
        ClientConnection(server, mgr, addr, port, socks5), EBStreamUV(connection) {}
};

NS_PROXY_CLIENT_END

