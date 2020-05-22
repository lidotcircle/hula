#pragma once

#include <uv.h>

#include <string>
#include <vector>
#include <tuple>
#include <map>
#include <unordered_set>

#include "../include/robuf.h"
#include "../include/utils.h"
#include "../include/events.h"
#include "../include/config_file.h"
#include "../include/dlinkedlist.hpp"
#include "../include/socks5.h"

// forward declaration
namespace UVC {struct UVCBaseClient;}


namespace KProxyClient {

class Server;
class ConnectionProxy;
class ClientProxy;
class RelayConnection;

enum ConnectionState {
    CONNECTION_INIT = 0,
    CONNECTION_OPEN,
    CONNECTION_CLOSING,
    CONNECTION_CLOSED
};

// FIXME CALLBACK MEMORY LEAK

/**
 * @class Socks5Auth */
class Socks5Auth //{
{
    public:
        using finish_cb = void (*)(int status, Socks5Auth* self_ref, const std::string& addr, 
                uint16_t port, uv_tcp_t* tcp, void* data);
        enum SOCKS5_STAGE {
            SOCKS5_ERROR = 0,
            SOCKS5_INIT,
            SOCKS5_ID,
            SOCKS5_METHOD,
            SOCKS5_FINISH
        };

    private:
        finish_cb m_cb;
        bool m_client_read_start;

        SOCKS5_STAGE  m_state;
        uv_loop_t*    mp_loop;
        uv_tcp_t*     mp_client;
        ClientConfig* mp_config;
        Server*       mp_server;
        ROBuf         m_remain;
        void*         m_data;

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
        Socks5Auth(Server* server, uv_tcp_t* client, ClientConfig* config, finish_cb cb, void* data);

        inline void send_reply(uint8_t reply) {this->__send_reply(reply);}

        inline ~Socks5Auth(){assert(uv_handle_get_data((uv_handle_t*)this->mp_client) == nullptr);}

        void close();
}; //}

/**
 * @class Server a socks5 proxy server */
class Server: EventEmitter //{
{
    private:
        bool exit__ = false;
        bool run___ = false;

        uint32_t bind_addr;
        uint16_t bind_port;

        // uv data structures
        uv_loop_t* mp_uv_loop;
        uv_tcp_t*  mp_uv_tcp;

        ClientConfig* m_config;

        // bool indicate bypass or proxy
        std::unordered_map<Socks5Auth*, std::tuple<bool, RelayConnection*>> m_auths;
        std::unordered_set<RelayConnection*> m_relay;

        std::unordered_set<UVC::UVCBaseClient*> m_callback_list;

//        ConnectionState m_state; TODO

        static void on_connection(uv_stream_t* stream, int status);

        /** this callback function is used to close Socks5Auth handle, 
         *  build a connection the endpoint is specified by @addr:@port and 
         *  transfer connection to relay service. 
         *  1. when (@con == nullptr), which means to make a connection to @addr:@port
         *     and then call the @self_ref->__send_reply(uint8_t) with status
         *  2. when (@con != nullptr && status < 0) means dispose Socks5Auth object and relay object
         *  3. when (@con != nullptr && status > 0) means dispose object and transfer connection to relay */
        static void on_authentication(int status, Socks5Auth* self_ref, 
                const std::string& addr, uint16_t port, 
                uv_tcp_t* con, void* data);

        static void on_config_load(int error, void* data);
        int __listen();

        void dispath_base_on_addr(const std::string&, uint16_t, Socks5Auth* socks5);
        void dispath_bypass(const std::string&, uint16_t, Socks5Auth* socks5);

        void redispatch(uv_tcp_t* client_tcp, Socks5Auth* socks5);

        void try_close();

    public:
        Server(const Server&) = delete;
        Server(Server&& s) = delete;
        Server& operator=(const Server&) = delete;
        Server& operator=(const Server&&) = delete;

        Server(uv_loop_t* loop, const std::string& config_file);

        int listen();
        void close();

        void callback_insert(UVC::UVCBaseClient* ptr);
        void callback_remove(UVC::UVCBaseClient* ptr);

        void close_relay(RelayConnection* relay);

        ~Server();

        inline bool IsRunning() {return this->run___;}
}; //}

/**
 * @class represent a socks5 connection */
class ClientConnection: EventEmitter //{
{
    private:
        uv_tcp_t* mp_tcp;
        Server* mp_server;
        ConnectionProxy* mp_proxy;
        uint8_t m_id;

        ConnectionState m_state;

        void socks5_authenticate();

    public:
        ClientConnection(const sockaddr* addr, Server* p);

        ClientConnection(const ClientConnection&) = delete;
        ClientConnection(ClientConnection&& a) = delete; 
        ClientConnection& operator=(ClientConnection&) = delete;
        ClientConnection& operator=(ClientConnection&&) = delete;

        int write(ROBuf buf);
        void close();
}; //}

/**
 * @class ConnectionProxy Multiplexing a single ssl/tls connection to multiple tcp connection */
class ConnectionProxy: EventEmitter //{
{
    private:
        std::map<uint8_t, ClientProxy*> m_map;
        Server* m_server;
        uv_tcp_t* m_connection;

        ConnectionState m_state;

        void tsl_handshake();
        void client_autheticate();

    public:
        ConnectionProxy(Server* server);

        ConnectionProxy(const ConnectionProxy&) = delete;
        ConnectionProxy(ConnectionProxy&& a) = delete;
        ConnectionProxy& operator=(ConnectionProxy&&);
        ConnectionProxy& operator=(const ConnectionProxy&) = delete;

        int write(uint8_t id,ROBuf buf);
        void close();

        inline size_t getConnectionNumbers() {return this->m_map.size();}
}; //}

/**
 * @class RelayConnection direct relay connection between webserver and client */
class RelayConnection: EventEmitter //{
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

