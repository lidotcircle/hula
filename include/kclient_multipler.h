#pragma once

#include "kclient.h"

NS_PROXY_CLIENT_START

/**
 * @class ConnectionProxy Multiplexing a single ssl/tls connection to multiple tcp connection */
class ConnectionProxy: public ProxyMultiplexerAbstraction //{
{
    public:
        // this callback should delete buf
        using WriteCallback = void (*)(bool should_run, int status, ROBuf* buf, void* data);
        using ConnectCallback = void (*)(bool should_run, int status, void* data);


   private:
        std::map<uint8_t, ClientProxyAbstraction*> m_map;
        std::set<uint8_t> m_wait_new_connection;

        Server*    mp_server;

        bool m_in_read;

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

        size_t m_out_buffer_size;

        /*
        ConnectCallback m_connect_cb;
        void*           m_connect_cb_data;
        */

        void client_authenticate();

        uint8_t get_id();

        // static void connect_remote_getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* info);
        static void connect_remote_callback(int status, void* data);

        void connect_to_with_sockaddr(sockaddr* sock);

        int _write(ROBuf buf, WriteCallback cb, void* data);
        static void _write_callback(uv_write_t* req, int status);

        int send_authentication_info();

        void connect_to_remote_server();

        static void on_authentication_write(bool should_run, int status, ROBuf* buf, void* data);

        static void uv_stream_read_after_send_auth_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
        void authenticate_with_remains();
        static void uv_stream_read_packet(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

        void dispatch_data_encrypted(ROBuf buf);
        void dispatch_data(ROBuf buf);

        static void new_connection_callback_wrapper(bool should_run, int status, ROBuf* buf, void* data);
        static void new_connection_timer_callback(uv_timer_t* timer);


   public:
        ConnectionProxy(uv_loop_t* loop, Server* server, SingleServerInfo* server_info);

        ConnectionProxy(const ConnectionProxy&) = delete;
        ConnectionProxy(ConnectionProxy&& a) = delete;
        ConnectionProxy& operator=(ConnectionProxy&&);
        ConnectionProxy& operator=(const ConnectionProxy&) = delete;

        int  write(uint8_t id, ROBuf buf, WriteCallback cb, void* data);
        enum CloseReason {
            CLOSE_NO_ERROR,
            CLOSE_REMOTE_SERVER_DNS,
            CLOSE_REMOTE_SERVER_CONNECT_ERROR,
            CLOSE_TLS_ERROR,
            CLOSE_AUTHENTICATION_ERROR,
            CLOSE_WRITE_ERROR,
            CLOSE_READ_ERROR,
            CLOSE_PACKET_ERROR,
            CLOSE_ID_ERROR,
            CLOSE_OPCODE_ERROR,
            CLOSE_REQUIRED,
        };
        void close(CloseReason reason);

        int new_connection  (uint8_t id, 
                             const std::string& addr, uint16_t port, 
                             WriteCallback cb, void* data);
        int close_connection(uint8_t id, WriteCallback cb, void* data);

        /** remove a ClientConnection object, and release the id associated with the object
         * @param {uint8_t id} this id should exists, otherwise assert(false);
         * @param {ClientConnection* obj} pointer to the object
         */
        void remove_connection(uint8_t id, ClientConnection* obj);

        /** connect to KProxyServer::Server endpoint
         * @param {ConnectCallback cb} when connecting is end either success or fail, #cb will be called with 
         *                             proper arguments
         * @param {void* data} a pointer pass to #cb
         */
        void connect(ConnectCallback cb, void* data);

        inline size_t getConnectionNumbers() {return this->m_map.size();}
        inline bool   IsIdFull() {return this->getConnectionNumbers() == SINGLE_TSL_MAX_CONNECTION;}
        inline bool   IsConnected() {return this->m_state == __State::STATE_BUILD;}

        /** register a ClientConnection object, and allocate an id to this object
         * @precondition assert(this.IsIdFull() == false)
         * @param {ClientConnection* obj) the object
         */
        uint8_t requireAnId(ClientConnection* obj);

        ~ConnectionProxy();
}; //}


NS_PROXY_CLIENT_END

