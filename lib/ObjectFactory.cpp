#include "../include/ObjectFactory.h"
#include "../include/kserver_libuv.h"
#include "../include/kclient_libuv.h"
#include "../include/stream_byprovider.h"


namespace Factory {
    using UNST = EBStreamAbstraction::UNST;

    KProxyServer::Server* createServer(std::shared_ptr<ServerConfig> config, void* connection) {
        return new KProxyServer::UVServer((uv_tcp_t*)connection, config);
    }
    KProxyServer::ConnectionProxyAbstraction* createConnectionProxy(KProxyServer::Server* server, UNST connection) {
        return new KProxyServer::UVMultiplexer(EBStreamUV::getStreamFromWrapper(connection), server);
    }
    KProxyServer::ToNetAbstraction* createToNet(KProxyServer::ClientConnectionProxy* proxy, EBStreamObject* stream, 
                                                UNST connection, StreamProvider::StreamId id, 
                                                const std::string& addr, uint16_t port) {
        return new KProxyServer::UVToNet(proxy, stream, connection, id, addr, port);
    }

    EBStreamObject* createUVStreamObject(size_t max_write_buffer_size, UNST connection) {
        assert(connection->getType() == StreamType::LIBUV);
        return new EBStreamObjectUV(EBStreamUV::getStreamFromWrapper(connection), max_write_buffer_size);
    }
    EBStreamObject* createKProxyMultiplexerStreamObject(size_t max_write_buffer_size, KProxyMultiplexerStreamProvider* provider) {
        return new EBStreamObjectKProxyMultiplexerProvider(provider, max_write_buffer_size); // TODO
    }

    namespace KProxyClient {
        Server*                      createServer(std::shared_ptr<ClientConfig> config, UNST connection) {
            if(connection->getType() == StreamType::LIBUV) {
                return new KProxyClient::UVServer(config, connection);
            } else {
                assert(false && "nope");
            }
        }
        Socks5ServerAbstraction*     createSocks5Server(Server* server, std::shared_ptr<ClientConfig> config, UNST connection) {
            return new KProxyClient::UVSocks5Auth(server, config, EBStreamUV::getStreamFromWrapper(connection));
        }
        RelayAbstraction*            createRelay(Server* server, Socks5ServerAbstraction* socks5,
                                                 const std::string& addr, uint16_t port,  UNST connection) {
            return new KProxyClient::UVRelay(server, socks5, addr, port, connection);
        }
        ClientProxyAbstraction*      createProxy(Server* server, ProxyMultiplexerAbstraction* mgr, 
                                                 const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5) {
            return new KProxyClient::UVClientConnection(server, mgr, addr, port, socks5);
        }
        ProxyMultiplexerAbstraction* createMultiplexer(Server* server, SingleServerInfo* config, UNST connection) {
            return new KProxyClient::UVMultiplexer(server, config, EBStreamUV::getStreamFromWrapper(connection));
        }
    };
};

