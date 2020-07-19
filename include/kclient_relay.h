#pragma once

#include "kclient.h"
#include "StreamRelay.h"


NS_PROXY_CLIENT_START

/**
 * @class RelayConnection direct relay connection between webserver and client */
class RelayConnection: public RelayAbstraction, public StreamRelay //{
{
    private:
        std::string m_addr;
        uint16_t    m_port;

        Server* m_kserver;
        Socks5ServerAbstraction* mp_socks5;

        bool m_closed;
        static void server_connect_listener(EventEmitter* em, const std::string& event, EventArgs::Base* args);


    protected:
        void __close() override;


    public:
        RelayConnection(Server* kserver, Socks5ServerAbstraction* socks5, 
                        const std::string& server, uint16_t port, EBStreamAbstraction::UNST server_connection);

        void run(Socks5ServerAbstraction* socks5) override;
        void connectToAddr() override;
        void close() override;

        void getStream(EBStreamAbstraction::UNST) override;

        ~RelayConnection();
}; //}


NS_PROXY_CLIENT_END

