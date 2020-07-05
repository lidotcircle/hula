#pragma once

#include "kserver.h"
#include "kserver_server.h"
#include "stream.hpp"

NS_PROXY_SERVER_START

class ToNetAbstraction: virtual protected EBStreamAbstraction {
    public:
        virtual void close() = 0;
        virtual void connect_to() = 0;
        virtual void PushData(ROBuf buf) = 0;
        virtual void startRead() = 0;
        virtual void stopRead() = 0;
        virtual void endSignal() = 0;
};

/**
 * @class ClientConnectionProxy Multiplexing a single ssl/tls connection to multiple tcp connection */
class ClientConnectionProxy: public ConnectionProxyAbstraction, private CallbackManager //{
{
    public:
        using WriteCallback = void (*)(ROBuf buf, void* data, int status, bool run);

    private:
        std::map<uint8_t, ToNetAbstraction*> m_map;
        std::set<uint8_t> m_wait_connect;
        Server* mp_server;

        size_t m_user_to_net_buffer = 0;
        size_t m_net_to_user_buffer = 0;

        ROBuf m_remains;

        static void write_to_user_stream_cb(ROBuf buf, int status, void* data);

        bool in_authentication;
        void dispatch_new_data(ROBuf buf);
        void dispatch_authentication_data(ROBuf buf);
        void dispatch_packet_data(ROBuf buf);

        void dispatch_reg  (uint8_t id, ROBuf buf);  // OPCODE PACKET_OP_REG
        void dispatch_new  (uint8_t id, ROBuf buf);  // OPCODE PACKET_OP_NEW
        void dispatch_close(uint8_t id, ROBuf buf);  // OPCODE PACKET_OP_CLOSE

        int __write(ROBuf buf, WriteCallback cb, void* data);
        void send_simple_packet(uint8_t id, PACKET_OPCODE opcode, ToNetAbstraction* net);


    protected:
        void read_callback(ROBuf buf, int status) override;
        void end_signal() override;


    public:
        ClientConnectionProxy(Server* server);
        void start() override;

        ClientConnectionProxy(const ClientConnectionProxy&) = delete;
        ClientConnectionProxy(ClientConnectionProxy&& a) = delete;
        ClientConnectionProxy& operator=(ClientConnectionProxy&&) = delete;
        ClientConnectionProxy& operator=(const ClientConnectionProxy&) = delete;

        int close_connection (uint8_t id);
        int accept_connection(uint8_t id);
        int reject_connection(uint8_t id, NEW_CONNECTION_REPLY reason);

        void remove_connection(uint8_t id, ToNetAbstraction* con);

        void send_connection_end(uint8_t id, ToNetAbstraction*) override;
        void send_connection_start_read(uint8_t id, ToNetAbstraction*) override;
        void send_connection_stop_read(uint8_t id, ToNetAbstraction*) override;

        void close() override;

        int write(uint8_t id, ROBuf buf, WriteCallback cb, void* data);

        void start_relay();

        inline size_t getConnectionNumbers() {return this->m_map.size();}
}; //}

NS_PROXY_SERVER_END

