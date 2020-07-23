#pragma once

#include "kserver.h"
#include "kserver_server.h"
#include "kserver_multiplexer.h"
#include "kserver_server2net.h"

#include "stream.h"
#include "stream_libuv.h"
#include "stream_libuvTLS.h"

NS_PROXY_SERVER_START


class UVServer:       virtual public EBStreamUV, public Server {
    public:
        inline UVServer(uv_tcp_t* connection, std::shared_ptr<ServerConfig> config): 
            EBStreamUV(connection), Server(config) {}
};

class UVMultiplexer: virtual public EBStreamUV, public ClientConnectionProxy {
    public:
        inline UVMultiplexer(uv_tcp_t* connection, Server* server):
            EBStreamUV(connection), ClientConnectionProxy(server) {}
};


class UVToNet: public ServerToNetConnection {
    public:
        inline UVToNet(ClientConnectionProxy* proxy, EBStreamObject* obj, EBStreamAbstraction::UNST connection, 
                       StreamProvider::StreamId id, const std::string& addr, uint16_t port):
            ServerToNetConnection(proxy, obj, connection, id, addr, port) {
                assert(connection->getType() == StreamType::LIBUV);
            }
};


class UVTLSServer: virtual public EBStreamUVTLS, public Server {
    public:
        inline UVTLSServer(uv_tcp_t* connection, std::shared_ptr<ServerConfig> config):
            EBStreamUVTLS(connection, TLSMode::ServerMode, config->Cert(), config->PrivateKey()), Server(config) {}
};

class UVTLSMultiplexer: virtual EBStreamUVTLS, public ClientConnectionProxy {
    public:
        inline UVTLSMultiplexer(UNST connection, Server* server):
            EBStreamUVTLS(connection), ClientConnectionProxy(server) {}
};


NS_PROXY_SERVER_END
