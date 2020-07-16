#pragma once

#include "kserver.h"
#include "kserver_server.h"
#include "kserver_multiplexer.h"
#include "kserver_server2net.h"

#include "stream.hpp"
#include "stream_libuv.hpp"

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
        inline UVToNet(ClientConnectionProxy* proxy, EBStreamObject* obj, uv_tcp_t* connection, 
                       StreamProvider::StreamId id, const std::string& addr, uint16_t port):
            ServerToNetConnection(proxy, obj, connection, id, addr, port) {}
};


NS_PROXY_SERVER_END
