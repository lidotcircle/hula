#pragma once

#include "kclient.h"

NS_PROXY_CLIENT_START

/**
 * @class represent a socks5 connection */
class ClientConnection: public ClientProxyAbstraction //{
{
    private:
        ProxyMultiplexerAbstraction* mp_proxy;

        bool m_client_start_read;
        bool m_server_start_read;

        Server* mp_kserver;
        uint8_t m_id;

        Socks5ServerAbstraction* m_socks5;

        std::string m_addr;
        uint16_t    m_port;

        bool m_closed;

        size_t m_write_to_client_buffer;
        size_t m_write_to_server_buffer;

        bool m_client_end;
        bool m_server_end;

        void __start_relay();
        void __relay_client_to_server();
        void __relay_server_to_client();
        void __stop_relay_client_to_server();
        void __stop_relay_server_to_client();

        static void write_to_client_callback(ROBuf buf, int status, void* data);
        static void multiplexer_connect_callback(int status, void* data);

        void __connect();


    protected:
        void read_callback(ROBuf buf, int status) override;
        void end_signal() override;

        void sendServerEnd() override;
        void startServerRead() override;
        void stopServerRead() override;


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

        void pushData(ROBuf buf) override;
        void serverEnd() override;

        void connectSuccess() override;
        void connectFail(ConnectResult) override;
}; //}

NS_PROXY_CLIENT_END
