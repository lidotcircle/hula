#pragma once

#include "kclient.h"


NS_PROXY_CLIENT_START

/**
 * @class RelayConnection direct relay connection between webserver and client */
class RelayConnection: public RelayAbstraction //{
{
    private:
        bool m_client_start_read;
        bool m_server_start_read;

        std::string m_addr;
        uint16_t    m_port;

        Server* m_kserver;
        Socks5ServerAbstraction* mp_socks5;

        bool m_closed;

        EBStreamObject *mp_client_manager, *mp_server_manager;

        void *m_client_drain_listener_reg, *m_server_drain_listener_reg;

        void register_server_listener();
        void register_client_listener();
        static void client_data_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);
        static void server_data_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);

        static void client_drain_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);
        static void server_drain_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);

        static void client_end_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);
        static void server_end_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);

        static void client_error_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);
        static void server_error_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);

        static void server_connect_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);

        void __start_relay();

        void __relay_client_to_server();
        void __relay_server_to_client();

    public:
        RelayConnection(Server* kserver, Socks5ServerAbstraction* socks5, 
                        const std::string& server, uint16_t port, void* server_connection);

        void run(Socks5ServerAbstraction* socks5) override;
        void connectToAddr() override;
        void close() override;

        void getStream(void*) override;

        ~RelayConnection();
}; //}


NS_PROXY_CLIENT_END

