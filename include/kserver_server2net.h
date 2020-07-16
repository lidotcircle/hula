#pragma once

#include "kserver_multiplexer.h"
#include "object_manager.h"

NS_PROXY_SERVER_START

/**
 * @class ServerToNetConnection Proxy a single tcp connection. When new packet arrives, relay the packet to client */
class ServerToNetConnection: public ToNetAbstraction, virtual protected CallbackManager //{
{
    private:
        bool m_inform_client_stop_read;

        ClientConnectionProxy* mp_proxy;
        ConnectionId m_id;

        size_t m_net_to_user_buffer;
        size_t m_user_to_net_buffer;

        bool m_one_say_end;
        bool m_has_recieved_end;

        std::string m_addr;
        uint16_t    m_port;

        void __connect();
        static void tcp2net_getaddrinfo_callback(struct addrinfo* res, void(*freeaddrinfo)(struct addrinfo*), int status, void* data);
        void __connect_with_sockaddr(sockaddr* addr);
        static void tcp2net_connect_callback(int status, void* data);
        static void tcp2net_write_callback  (ROBuf buf, int status, void* data);

        void __start_net_to_user();
        void __stop_net_to_user();
        void __start_user_to_net();
        void __stop_user_to_net();

        inline bool user_in_read() {return !this->m_inform_client_stop_read;}

        void _write_to_user(ROBuf buf);
        static void write_to_user_callback(ROBuf buf, void* data, int status, bool run);

        static void end_signal_shutdown_callback(int status, void*);

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

        void startRead() override;
        void stopRead() override;
        void endSignal() override;

        ~ServerToNetConnection();
}; //}

NS_PROXY_SERVER_END
