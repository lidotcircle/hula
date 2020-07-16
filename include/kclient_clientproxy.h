#pragma once

#include "kclient.h"
#include "StreamRelay.h"

NS_PROXY_CLIENT_START

/**
 * @class represent a socks5 connection */
class ClientConnection: public ClientProxyAbstraction, public StreamRelay  //{
{
    private:
        ProxyMultiplexerAbstraction* mp_proxy;

        Server* mp_kserver;
        Socks5ServerAbstraction* m_socks5;

        std::string m_addr;
        uint16_t    m_port;

        bool m_closed;

        static void multiplexer_connect_callback(int status, void* data);
        static void connect_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* args);

        void __connect();


    public:
        ClientConnection(Server* kserver, ProxyMultiplexerAbstraction* mproxy, 
                         const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5);

        ClientConnection(const ClientConnection&) = delete;
        ClientConnection(ClientConnection&& a) = delete; 
        ClientConnection& operator=(ClientConnection&) = delete;
        ClientConnection& operator=(ClientConnection&&) = delete;

        void close() override;
        void connectToAddr() override;
        void run(Socks5ServerAbstraction*) override;
        void getStream(void*) override;

        void __close() override;
}; //}

NS_PROXY_CLIENT_END

