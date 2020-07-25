#include "../include/ObjectFactory.h"
#include "../include/kserver_libuv.h"
#include "../include/kclient_libuv.h"
#include "../include/stream_object_libuv.h"
#include "../include/stream_byprovider.h"

#include "../include/http_file_server_libuvTLS.h"


namespace Factory {
    using UNST = EBStreamAbstraction::UNST;

    namespace KProxyServer {
        Server* createServer(std::shared_ptr<ServerConfig> config, void* connection) {
            return new KProxyServer::UVServer((uv_tcp_t*)connection, config);
        }
        Server* createUVTLSServer(std::shared_ptr<ServerConfig> config, uv_tcp_t* connection) {
            return new UVTLSServer(connection, config);
        }
        ConnectionProxyAbstraction* createConnectionProxy(Server* server, UNST connection) {
            switch(connection->getType()) {
                case StreamType::LIBUV:
                    return new UVMultiplexer(EBStreamUV::getStreamFromWrapper(connection), server);
                case StreamType::TLS_LIBUV:
                    return new UVTLSMultiplexer(connection, server);
                default:
                    return nullptr;
            }
        }
        ToNetAbstraction* createToNet(ClientConnectionProxy* proxy, EBStreamObject* stream, 
                                      UNST connection, StreamProvider::StreamId id, 
                                      const std::string& addr, uint16_t port) {
            switch(connection->getType()) {
                case StreamType::LIBUV:
                    return new KProxyServer::UVToNet(proxy, stream, connection, id, addr, port);
                case StreamType::TLS_LIBUV:
                    {
                        auto ctx = EBStreamTLS::getCTXFromWrapper(connection);
                        auto fffstream = ctx->mp_stream;
                        ctx->mp_stream = nullptr;
                        EBStreamTLS::releaseCTX(ctx);
                        auto thestream = fffstream->transfer();
                        delete fffstream;
                        return new KProxyServer::UVToNet(proxy, stream, thestream, id, addr, port);
                    }
                default:
                    return nullptr;
            }
        }
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
        ProxyMultiplexerAbstraction* createUVTLSMultiplexer(Server* server, SingleServerInfo* config, UNST connection) {
            return new KProxyClient::UVTLSMultiplexer(server, config, EBStreamUV::getStreamFromWrapper(connection));
        }
    };

    namespace Filesystem {
        FileAbstraction* createUVFile(const std::string& filename, uv_loop_t* loop) {
            return new UVFile(loop, filename);
        }
    }

    namespace Config {
        HttpFileServerConfig* createHttpFileServerConfig(const std::string& filename, FileAbstraction::FileMechanism mm) //{
        {
            switch(mm->getType()) {
                case FileMechanismType::LIBUV:
                    {
                        __UVFileMechanism* mmm = dynamic_cast<decltype(mmm)>(mm.get());
                        assert(mmm);
                        return new UVHttpFileServerConfig(mmm->m_loop, filename);
                    }
                default:
                    return nullptr;
            }
        } //}
    }

    namespace Web {
        Http* createHttpSession(UNST con, const std::unordered_map<std::string, std::string>& default_header) //{
        {
            switch(con->getType()) {
                case StreamType::LIBUV:
                    return new UVHttp(default_header, EBStreamUV::getStreamFromWrapper(con));
                case StreamType::TLS_LIBUV:
                    return new UVTLSHttp(default_header, con);
                default:
                    return nullptr;
            }
        } //}

        HttpFileServer* createHttpFileServer(UNST con, std::shared_ptr<HttpFileServerConfig> config) //{
        {
            switch(con->getType()) {
                case StreamType::LIBUV:
                    return new UVHttpFileServer(config, EBStreamUV::getStreamFromWrapper(con));
                case StreamType::TLS_LIBUV:
                    return new UVTLSHttpFileServer(config, con);
                default:
                    return nullptr;
            }
        } //}
        HttpFileServer* createUVTLSHttpFileServer(std::shared_ptr<HttpFileServerConfig> config, uv_tcp_t* tcp, //{
                                                  const std::string& cert, const std::string& privateKey)
        {
            return new UVTLSHttpFileServer(config, tcp, cert, privateKey);
        } //}

    }
};

