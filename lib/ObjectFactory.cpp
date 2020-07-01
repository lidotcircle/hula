#include "../include/ObjectFactory.hpp"
#include "../include/kserver_libuv.h"


namespace Factory {
    KProxyServer::Server* createServer(std::shared_ptr<ServerConfig> config, void* connection) {
        return new KProxyServer::UVServer((uv_tcp_t*)connection, config);
    }
    KProxyServer::ConnectionProxyAbstraction* createConnectionProxy(KProxyServer::Server* server, void* connection) {
        return new KProxyServer::UVMultiplexing((uv_tcp_t*)connection, server);
    }
    KProxyServer::ToNetAbstraction* createToNet(KProxyServer::ClientConnectionProxy* proxy, void* connection, uint8_t id, const std::string& addr, uint16_t port) {
        return new KProxyServer::UVToNet((uv_tcp_t*)connection, proxy, id, addr, port);
    }
};

