#include "../include/ObjectFactory.hpp"
#include "../include/kserver_libuv.h"
#include "../include/kclient_libuv.h"
#include "../include/stream_byprovider.h"


namespace Factory {
    KProxyServer::Server* createServer(std::shared_ptr<ServerConfig> config, void* connection) {
        return new KProxyServer::UVServer((uv_tcp_t*)connection, config);
    }
    KProxyServer::ConnectionProxyAbstraction* createConnectionProxy(KProxyServer::Server* server, void* connection) {
        return new KProxyServer::UVMultiplexer((uv_tcp_t*)connection, server);
    }
    KProxyServer::ToNetAbstraction* createToNet(KProxyServer::ClientConnectionProxy* proxy, EBStreamObject* stream, 
                                                void* connection, StreamProvider::StreamId id, 
                                                const std::string& addr, uint16_t port) {
        return new KProxyServer::UVToNet(proxy, stream, (uv_tcp_t*)connection, id, addr, port);
    }

    EBStreamObject* createUVStreamObject(size_t max_write_buffer_size, void* connection) {
        return new EBStreamObjectUV((uv_tcp_t*)connection, max_write_buffer_size);
    }
    EBStreamObject* createKProxyMultiplexerStreamObject(size_t max_write_buffer_size, KProxyMultiplexerStreamProvider* provider) {
        return new EBStreamObjectKProxyMultiplexerProvider(provider, max_write_buffer_size);
    }

    namespace KProxyClient {
        Server*                      createServer(std::shared_ptr<ClientConfig> config, void* connection) {
            return new KProxyClient::UVServer(config, (uv_tcp_t*)connection);
        }
        Socks5ServerAbstraction*     createSocks5Server(Server* server, std::shared_ptr<ClientConfig> config, void* connection) {
            return new KProxyClient::UVSocks5Auth(server, config, (uv_tcp_t*)connection);
        }
        RelayAbstraction*            createRelay(Server* server, Socks5ServerAbstraction* socks5,
                                                 const std::string& addr, uint16_t port, void* connection) {
            return new KProxyClient::UVRelay(server, socks5, addr, port, (uv_tcp_t*)connection);
        }
        ClientProxyAbstraction*      createProxy(Server* server, ProxyMultiplexerAbstraction* mgr, 
                                                 const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5) {
            return new KProxyClient::UVClientConnection(server, mgr, addr, port, socks5);
        }
        ProxyMultiplexerAbstraction* createMultiplexer(Server* server, SingleServerInfo* config, void* connection) {
            return new KProxyClient::UVMultiplexer(server, config, (uv_tcp_t*)connection);
        }
    };
};

