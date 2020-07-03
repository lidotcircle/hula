#pragma once

#include "kclient.h"

NS_PROXY_CLIENT_START

/**
 * @class ConnectionProxy Multiplexing a single ssl/tls connection to multiple tcp connection */
class ConnectionProxy: public ProxyMultiplexerAbstraction //{
{
    public:
        // this callback should delete buf
        using WriteCallback = void (*)(int status, ROBuf* buf, void* data);
        using ConnectCallback = void (*)(int status, void* data);


   private:
        std::map<uint8_t, ClientProxyAbstraction*> m_map;
        std::set<uint8_t> m_wait_new_connection;

        Server*    mp_server;
        SingleServerInfo* mp_server_info;

        ROBuf m_remain;

        enum __State {
            STATE_INITIAL = 0,
            STATE_CONNECTING,
            STATE_AUTH,
            STATE_WAIT_AUTH_REPLY,
            STATE_BUILD,
            STATE_CLOSING,
            STATE_CLOSED,
            STATE_ERROR
        };
        __State m_state;

        /** statistics */
        size_t m_total_write_to_client_buffer;
        size_t m_total_write_to_server_buffer;

        ConnectCallback m_connect_cb;
        void*           m_connect_cb_data;


    protected:
        void read_callback(ROBuf, int status) override;
        void end_signal() override;


    private:
        uint8_t get_id();

        void __connectToServer(ConnectCallback cb, void* data);
        static void connect_to_remote_server_callback(int status, void* data);

        void send_authentication_info();
        static void on_authentication_write(ROBuf buf, int status, void* data);

        void authenticate(ROBuf buf);
        void dispatch_data(ROBuf buf);

        static void new_connection_write_callback(ROBuf buf, int status, void* data);
        static void new_connection_timer_callback(void* data);

        void send_close_connection(uint8_t id);


   public:
        ConnectionProxy(Server* server, SingleServerInfo* server_info);

        ConnectionProxy(const ConnectionProxy&) = delete;
        ConnectionProxy(ConnectionProxy&& a) = delete;
        ConnectionProxy& operator=(ConnectionProxy&&);
        ConnectionProxy& operator=(const ConnectionProxy&) = delete;

        void connectToServer(ConnectCallback cb, void* data) override;
        void new_connection(uint8_t id, ClientProxyAbstraction* obj, 
                            const std::string& addr, uint16_t port, int timeout_ms) override;
        void remove_clientConnection(uint8_t, ClientProxyAbstraction* obj) override;

        void sendStartConnectionRead(uint8_t) override;
        void sendStopConnectionRead (uint8_t) override;
        void connectionEnd(uint8_t id, ClientProxyAbstraction* obj) override;

        void write(uint8_t id, ClientProxyAbstraction* obj, ROBuf buf, WriteCallbackMM cb, void* data) override;

        uint8_t getConnectionNumbers() override;
        bool    connected() override;
        bool    full() override;
        uint8_t requireAnId(ClientProxyAbstraction*) override;
        bool    uninit() override;

        void close() override;
        ~ConnectionProxy();
}; //


NS_PROXY_CLIENT_END

