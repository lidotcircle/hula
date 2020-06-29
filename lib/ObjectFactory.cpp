#include "../include/ObjectFactory.hpp"
#include "../include/kserver_libuv.h"


namespace Factory {
    KProxyServer::Server* createServer(std::shared_ptr<ServerConfig> config) {
        return nullptr;
    }
    KProxyServer::ConnectionProxyAbstraction* createConnectionProxy(KProxyServer::Server* server, void* connection) {
        return nullptr;
    }
    KProxyServer::ToNetAbstraction* ToNetAbstraction(KProxyServer::ConnectionProxyAbstraction* proxy, void* connection, uint8_t id, const std::string& addr, uint16_t port) {
        return nullptr;
    }
};

