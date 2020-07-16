#pragma once

#include "kserver_multiplexer.h"
#include "object_manager.h"
#include "StreamRelay.h"

NS_PROXY_SERVER_START

/**
 * @class ServerToNetConnection Proxy a single tcp connection. When new packet arrives, relay the packet to client */
class ServerToNetConnection: public ToNetAbstraction, public StreamRelay //{
{
    private:
        ClientConnectionProxy* mp_proxy;
        StreamProvider::StreamId m_id;

        std::string m_addr;
        uint16_t    m_port;
        bool m_connected;

        static void connect_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* args);


    public:
        ServerToNetConnection(ClientConnectionProxy* proxy, EBStreamObject* obj, 
                              void* connection, StreamProvider::StreamId id, 
                              const std::string& addr, uint16_t port);

        ServerToNetConnection(const ServerToNetConnection&) = delete;
        ServerToNetConnection(ServerToNetConnection&& a) = delete;
        ServerToNetConnection& operator=(const ServerToNetConnection&) = delete;
        ServerToNetConnection& operator=(ServerToNetConnection&&) = delete;

        void connectToAddr() override;
        void __close() override;
        void close() override;
        ~ServerToNetConnection();
}; //}


NS_PROXY_SERVER_END

