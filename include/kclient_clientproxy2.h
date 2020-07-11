#pragma once

#include "kclient.h"
#include "StreamRelay.h"

NS_PROXY_CLIENT_START

/**
 * @class represent a socks5 connection */
class ClientConnection2: public ClientProxyAbstraction2, protected StreamRelay  //{
{
    private:
        ProxyMultiplexerAbstraction2* mp_proxy;

        Server* mp_kserver;
        Socks5ServerAbstraction* m_socks5;

        std::string m_addr;
        uint16_t    m_port;

        bool m_closed;

        static void multiplexer_connect_callback(int status, void* data);

        void __connect();


    public:
        ClientConnection2(Server* kserver, ProxyMultiplexerAbstraction2* mproxy, 
                         const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5);

        ClientConnection2(const ClientConnection2&) = delete;
        ClientConnection2(ClientConnection2&& a) = delete; 
        ClientConnection2& operator=(ClientConnection2&) = delete;
        ClientConnection2& operator=(ClientConnection2&&) = delete;

        void close() override;
        void connectToAddr() override;
        void run(Socks5ServerAbstraction*) override;
        void getStream(void*) override;
}; //}

NS_PROXY_CLIENT_END

