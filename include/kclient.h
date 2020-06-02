#pragma once

#include <uv.h>

#include <string>
#include <vector>
#include <tuple>
#include <map>
#include <unordered_set>
#include <set>

#include "../include/robuf.h"
#include "../include/utils.h"
#include "../include/events.h"
#include "../include/config_file.h"
#include "../include/dlinkedlist.hpp"
#include "../include/socks5.h"
#include "../include/object_manager.h"


#define SINGLE_TSL_MAX_CONNECTION (1 << 6)

// forward declaration
namespace UVC {struct UVCBaseClient;}


namespace KProxyClient {

class Server;
class ConnectionProxy;
class RelayConnection;

enum ConnectionState {
    CONNECTION_INIT = 0,
    CONNECTION_OPEN,
    CONNECTION_CLOSING,
    CONNECTION_CLOSED
};

class ClientConnection;


/**
 * @class Socks5Auth */
class Socks5Auth: public EventEmitter //{
{
    public:
    /*
        using finish_cb = void (*)(int status, Socks5Auth* self_ref, const std::string& addr, 
                uint16_t port, uv_tcp_t* tcp, void* data);
                */
        enum SOCKS5_STAGE {
            SOCKS5_ERROR = 0,
            SOCKS5_INIT,
            SOCKS5_ID,
            SOCKS5_METHOD,
            SOCKS5_FINISH
        };

    private:
        /*
        finish_cb m_cb;
        void*     m_data;
        */
        bool m_client_read_start;

        SOCKS5_STAGE  m_state;
        uv_loop_t*    mp_loop;
        uv_tcp_t*     mp_client;
        ClientConfig* mp_config;
        Server*       mp_server;
        ROBuf         m_remain;

        std::string   m_servername;
        uint16_t      m_port;

        void dispatch_data(ROBuf buf);

        static void read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

        static void write_callback_hello(uv_write_t* req, int status);
        static void write_callback_id(uv_write_t* req, int status);
        static void write_callback_reply(uv_write_t* req, int status);

        void return_to_server();
        void close_this_with_error();
        void try_to_build_connection();

        void __send_selection_method(socks5_authentication_method method);
        void __send_auth_status(uint8_t status);
        void __send_reply(uint8_t reply);

        void setup_uv_tcp_data();
        void clean_uv_tcp_data();

    public:
        Socks5Auth(Server* server, uv_tcp_t* client, ClientConfig* config/*, finish_cb cb, void* data */);

        inline void send_reply(uint8_t reply) {this->__send_reply(reply);}

        inline ~Socks5Auth(){assert(uv_handle_get_data((uv_handle_t*)this->mp_client) == nullptr);}

        void close();
}; //}

/**
 * @class Server a socks5 proxy server */
class Server: public EventEmitter, public ObjectManager //{
{
    /*
    public:
        using M_CB = void (*)(Server*, ConnectionProxy*, 
                              uint8_t id, const std::string& addr, 
                              uint16_t port, Socks5Auth* socks5, uint8_t socks5_reply);
                              */

    private:
        bool exit__ = false;
        bool run___ = false;

        uint32_t bind_addr;
        uint16_t bind_port;

        // uv data structures
        uv_loop_t* mp_uv_loop;
        uv_tcp_t*  mp_uv_tcp;

        ClientConfig* m_config;

    protected:
        friend class ConnectionProxy;
        std::unordered_map<Socks5Auth*, std::tuple<bool, EventEmitter*>> m_auths;
        std::unordered_set<RelayConnection*> m_relay;
        std::unordered_set<ConnectionProxy*> m_proxy;

    private:
        /** handler of connection event */
        static void on_connection(uv_stream_t* stream, int status);

        /** this callback function is used to close Socks5Auth handle, 
         *  build a connection the endpoint is specified by @addr:@port and 
         *  transfer connection to relay service. 
         *  1. when (@con == nullptr), which means to make a connection to @addr:@port
         *     and then call the @self_ref->__send_reply(uint8_t) with status
         *  2. when (@con != nullptr && status < 0) means dispose Socks5Auth object and relay object
         *  3. when (@con != nullptr && status > 0) means dispose object and transfer connection to relay 
        static void on_authentication(int status, Socks5Auth* self_ref, 
                const std::string& addr, uint16_t port, 
                uv_tcp_t* con, void* data);
                */

        static void on_config_load(int error, void* data);
        int __listen();

        void dispatch_base_on_addr(const std::string&, uint16_t, Socks5Auth* socks5);
        void dispatch_bypass(const std::string&, uint16_t, Socks5Auth* socks5);
        void dispatch_proxy (const std::string&, uint16_t, Socks5Auth* socks5);

        void redispatch(uv_tcp_t* client_tcp, Socks5Auth* socks5);

        /** implement strategy for selecting remote server */
        SingleServerInfo* select_remote_serever();

        void try_close();

    public:
        Server(const Server&) = delete;
        Server(Server&& s) = delete;
        Server& operator=(const Server&) = delete;
        Server& operator=(const Server&&) = delete;

        Server(uv_loop_t* loop, const std::string& config_file);

        int listen();
        void close();

        /** delete @relay object and inform this inform to callbacks related with this @relay */
        void remove_relay(RelayConnection* relay);
        /** delete @proxy object and inform this inform to callbacks related with this @proxy */
        void remove_proxy(ConnectionProxy* proxy);

        void socks5BuildConnection(Socks5Auth* socks5, const std::string& addr, uint16_t port);
        void socks5Transfer(Socks5Auth* socks5, uv_tcp_t* client_tcp);
        void socks5Reject(Socks5Auth* socks5, uv_tcp_t* client_tcp);

        ~Server();

        inline bool IsRunning() {return this->run___;}
}; //}

/**
 * @class represent a socks5 connection */
class ClientConnection: public EventEmitter //{
{
    public:
        struct __proxyWriteInfo {ClientConnection* _this; bool exited;};

    private:
        uv_loop_t* mp_loop;
        uv_tcp_t*  mp_tcp_client;
        ConnectionProxy* mp_proxy;

        bool m_client_start_read;

        Server* mp_kserver;
        uint8_t m_id;

        Socks5Auth* m_socks5;

        std::string m_server;
        uint16_t    m_port;

        enum __State {
            INITIAL = 0,
            CONNECTING,
            RUNNING,
            ERROR
        };
        __State m_state;
        std::unordered_set<__proxyWriteInfo*> m_proxy_write_callbacks;

        size_t      m_in_buffer;
        size_t      m_out_buffer;

        void __start_relay();
        static void client_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
        static void ProxyWriteCallback(bool should_run, int status, ROBuf* buf, void* data);

        static void write_to_client_callback(uv_write_t* req, int status);

        static void connect_callback(bool should_run, int status, void* data);
        void __connect(Socks5Auth* socks5);

    public:
        ClientConnection(Server* kserver, uv_loop_t* loop, ConnectionProxy* mproxy, 
                         const std::string& addr, uint16_t port, Socks5Auth* socks5);

        ClientConnection(const ClientConnection&) = delete;
        ClientConnection(ClientConnection&& a) = delete; 
        ClientConnection& operator=(ClientConnection&) = delete;
        ClientConnection& operator=(ClientConnection&&) = delete;

        void run(uv_tcp_t* client_tcp);
        void PushData(ROBuf buf);
        void connect(Socks5Auth* socks5);
        void close(bool send_close);

        void reject();
        void accept();

        inline bool IsRun() {return this->m_state == __State::RUNNING;}
}; //}

/**
 * @class ConnectionProxy Multiplexing a single ssl/tls connection to multiple tcp connection */
class ConnectionProxy: public EventEmitter //{
{
    public:
        // this callback should delete buf
        using WriteCallback = void (*)(bool should_run, int status, ROBuf* buf, void* data);
        using ConnectCallback = void (*)(bool should_run, int status, void* data);


   private:
        std::map<uint8_t, ClientConnection*> m_map;
        std::set<uint8_t> m_wait_new_connection;

        Server*    mp_server;
        uv_loop_t* mp_loop;

        uv_tcp_t* mp_connection;
        bool m_connection_read;

        SingleServerInfo* mp_server_info;

        ROBuf m_remain_raw;

        enum __State {
            STATE_INITIAL = 0,
            STATE_GETDNS,
            STATE_CONNECTING,
            STATE_TSL,
            STATE_AUTH,
            STATE_WAIT_AUTH_REPLY,
            STATE_BUILD,
            STATE_CLOSING,
            STATE_CLOSED,
            STATE_ERROR
        };
        __State m_state;

        size_t m_out_buffer;

        ConnectCallback m_connect_cb;
        void*           m_connect_cb_data;

        void tsl_handshake();
        void client_authenticate();

        uint8_t get_id();

        static void connect_remote_getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* info);
        static void connect_remote_tcp_connect_cb(uv_connect_t* req, int status);

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
         * @param {bool remove} whether delete the object, which may be clean by other function. CAREFUL
         */
        void remove_connection(uint8_t id, ClientConnection* obj, bool remove);

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

/**
 * @class RelayConnection direct relay connection between webserver and client */
class RelayConnection: public EventEmitter //{
{
    private:
        uv_loop_t* mp_loop;
        uv_tcp_t*  mp_tcp_client;
        uv_tcp_t*  mp_tcp_server;

        bool m_client_start_read;
        bool m_server_start_read;

        std::string m_server;
        uint16_t    m_port; // network bytes order -- big-endian

        size_t m_in_buffer;
        size_t m_out_buffer;

        Server* m_kserver;
        bool m_error;

        static void getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
        static void connect_server_cb(uv_connect_t* req, int status);

        static void client_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
        static void server_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

        static void server_write_cb(uv_write_t* req, int status);
        static void client_write_cb(uv_write_t* req, int status);

        void __connect_to(const sockaddr* addr, Socks5Auth* socks5);
        void __start_relay();

        void __relay_client_to_server();
        void __relay_server_to_client();

    public:
        RelayConnection(Server* kserver, uv_loop_t* loop, uv_tcp_t* tcp_client, const std::string& server, uint16_t port);
        void connect(Socks5Auth* socks5);
        void run(uv_tcp_t* client_tcp);
        void close();

        ~RelayConnection();
}; //}

}

