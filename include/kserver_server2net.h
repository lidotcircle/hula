#pragma once

#include "kserver_multiplexing.h"
#include "object_manager.h"

NS_PROXY_SERVER_START

/**
 * @class ServerToNetConnection Proxy a single tcp connection. When new packet arrives, relay the packet to client */
class ServerToNetConnection: public ToNetAbstraction, public CallbackManager //{
{
    private:
        bool m_inform_client_stop_read = false;

        ClientConnectionProxy* mp_proxy;
        ConnectionId m_id;

        size_t m_net_to_user_buffer;
        size_t m_user_to_net_buffer;

        bool m_net_tcp_start_read;

        std::string m_addr;
        uint16_t    m_port;

        void __connect();
        static void tcp2net_getaddrinfo_callback(struct addrinfo* res, void(*freeaddrinfo)(struct addrinfo*), int status, void* data);
        void __connect_with_sockaddr(sockaddr* addr);
        static void tcp2net_connect_callback(int status, void* data);
        static void tcp2net_write_callback  (ROBuf buf, int status, void* data);

        void __start_net_to_user();
        void _write_to_user(ROBuf buf);
        static void write_to_user_callback(ROBuf buf, void* data, int status, bool run);


    protected:
        void read_callback(ROBuf buf, int status) override;
        void end_signal() override;


    public:
        ServerToNetConnection(ClientConnectionProxy* proxy, ConnectionId id, 
                              const std::string& addr, uint16_t port);

        ServerToNetConnection(const ServerToNetConnection&) = delete;
        ServerToNetConnection(ServerToNetConnection&& a) = delete;
        ServerToNetConnection& operator=(const ServerToNetConnection&) = delete;
        ServerToNetConnection& operator=(ServerToNetConnection&&) = delete;

        void PushData(ROBuf buf) override;
        void close() override;
        void connect_to() override;

        ~ServerToNetConnection();
}; //}

NS_PROXY_SERVER_END
