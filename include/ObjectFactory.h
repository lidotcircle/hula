#pragma once

#include "kserver_server.h"
#include "kclient.h"
#include "StreamProvider_KProxyMultiplexer.h"
#include "StreamObject.h"

#include "http.h"                // web
#include "websocket.h"
#include "websocket_libuv.h"
#include "http_file_server.h"
#include "http_file_server_libuv.h"

#include "file.h"
#include "file_libuv.h"

#include "http_file_server_config.h"

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

    namespace Filesystem {
        FileAbstraction* createUVFile(const std::string& filename, uv_loop_t* loop);
    };

    namespace Config {
        HttpFileServerConfig* createHttpFileServerConfig(const std::string& filename, FileAbstraction::FileMechanism mm);

        ServerConfig* createServerConfig(const std::string& filename, FileAbstraction::FileMechanism mm);
        ClientConfig* createClientConfig(const std::string& filename, FileAbstraction::FileMechanism mm);
    };

    namespace Web {
        Http* createHttpSession(UNST con, const std::unordered_map<std::string, std::string>& default_header = {});

        WebSocketServer* createWSServer(UNST con);

        HttpFileServer* createHttpFileServer(UNST con, std::shared_ptr<HttpFileServerConfig> config);
        HttpFileServer* createUVTLSHttpFileServer(std::shared_ptr<HttpFileServerConfig> config, uv_tcp_t* tcp, 
                                                  const std::string& cert, const std::string& privateKey);
    };
};

