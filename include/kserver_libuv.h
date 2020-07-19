#pragma once

#include "kserver.h"
#include "kserver_server.h"
#include "kserver_multiplexer.h"
#include "kserver_server2net.h"

#include "stream.h"
#include "stream_libuv.h"

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


NS_PROXY_SERVER_END
