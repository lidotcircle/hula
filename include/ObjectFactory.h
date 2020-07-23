#pragma once

#include "kserver_server.h"
#include "kclient.h"
#include "StreamProvider_KProxyMultiplexer.h"
#include "StreamObject.h"

#include <memory>

NS_PROXY_SERVER_START
class Server;
class ConnectionProxyAbstraction;
class ToNetAbstraction;
NS_PROXY_SERVER_END

class ServerConfig;
using UNST = EBStreamAbstraction::UNST;

namespace Factory {
    namespace KProxyServer {
        using namespace ::KProxyServer;
        Server*                     createServer(std::shared_ptr<ServerConfig> config, UNST connection);
        Server*                     createUVTLSServer(std::shared_ptr<ServerConfig> config, uv_tcp_t* connection);
        ConnectionProxyAbstraction* createConnectionProxy(Server* server, UNST connection);
        ToNetAbstraction*           createToNet(ClientConnectionProxy* proxy, EBStreamObject* stream, 
                                                UNST connection, StreamProvider::StreamId id, 
                                                const std::string& addr, uint16_t port);
    }

    EBStreamObject* createUVStreamObject(size_t max_write_buffer_size, UNST connection);
    EBStreamObject* createKProxyMultiplexerStreamObject(size_t max_write_buffer_size, KProxyMultiplexerStreamProvider* provider);

    namespace KProxyClient {
        using namespace ::KProxyClient;
        Server*                      createServer(std::shared_ptr<ClientConfig> config, UNST connection);
        Socks5ServerAbstraction*     createSocks5Server(Server* server, std::shared_ptr<ClientConfig> config, UNST connection);
        RelayAbstraction*            createRelay(Server* server, Socks5ServerAbstraction* socks5,
                                                 const std::string& addr, uint16_t port, UNST connection);
        ClientProxyAbstraction*      createProxy(Server* server, ProxyMultiplexerAbstraction* mgr, 
                                                 const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5);
        ProxyMultiplexerAbstraction* createMultiplexer(Server* server, SingleServerInfo* config, UNST connection);
        ProxyMultiplexerAbstraction* createUVTLSMultiplexer(Server* server, SingleServerInfo* config, UNST connection);
    };
};

