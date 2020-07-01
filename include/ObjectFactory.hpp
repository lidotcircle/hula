#pragma once

#include "kserver_server.h"
#include "kclient.h"

#include <memory>

NS_PROXY_SERVER_START
class Server;
class ConnectionProxyAbstraction;
class ToNetAbstraction;
NS_PROXY_SERVER_END

class ServerConfig;

namespace Factory {
    KProxyServer::Server*                     createServer(std::shared_ptr<ServerConfig> config, void* connection);
    KProxyServer::ConnectionProxyAbstraction* createConnectionProxy(KProxyServer::Server* server, void* connection);
    KProxyServer::ToNetAbstraction*           createToNet(KProxyServer::ClientConnectionProxy* proxy, void* connection, 
                                                          uint8_t id, const std::string& addr, uint16_t port);

    EBStreamObject* createStreamObject(size_t max_write_buffer_size, void* connection);

    namespace KProxyClient {
        using namespace ::KProxyClient;
        Server*                      createServer(std::shared_ptr<ServerConfig> config, void* connection);
        Socks5ServerAbstraction*     createSocks5Server(Server* server, void* connection);
        RelayAbstraction*            createRelay(Server* server, Socks5ServerAbstraction* socks5,
                                                 const std::string& addr, uint16_t port, void* connection);
        ClientProxyAbstraction*      createProxy(ProxyMultiplexerAbstraction* mgr, const std::string& addr, uint16_t port, 
                                                 void* connection);
        ProxyMultiplexerAbstraction* createMultiplexer(SingleServerInfo* config, void* connection);
    };
};
