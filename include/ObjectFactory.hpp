#pragma once

#include "kserver_server.h"

#include <memory>

NS_PROXY_SERVER_START
class Server;
class ConnectionProxyAbstraction;
class ToNetAbstraction;
NS_PROXY_SERVER_END

class ServerConfig;

namespace Factory {
    KProxyServer::Server* createServer(std::shared_ptr<ServerConfig> config, void* connection);
    KProxyServer::ConnectionProxyAbstraction* createConnectionProxy(KProxyServer::Server* server, void* connection);
    KProxyServer::ToNetAbstraction* createToNet(KProxyServer::ClientConnectionProxy* proxy, void* connection, uint8_t id, const std::string& addr, uint16_t port);
};

