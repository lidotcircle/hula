#pragma once

#include <uv.h>

#include <string>
#include <vector>
#include <tuple>
#include <map>

namespace KProxyClient {

class Server;
class ConnectionProxy;
class ClientProxy;

/**
 * @class Server a socks5 proxy server */
class Server //{
{
    private:
        uint32_t bind_addr;
        uint16_t bind_port;

        // uv data structures
        uv_loop_t* mp_uv_loop;
        uv_tcp_t*  mp_uv_tcp;

        void init_this(uv_loop_t* p_loop, uv_tcp_t* p_tcp, uint32_t a, uint16_t p);

    public:
        Server(const Server&) = delete;
        inline Server(const Server&& s) {
            *this = static_cast<const Server&&>(s);
        }

        Server(uint32_t bind_addr, uint16_t bind_port);
        Server(const std::string& bind_addr, const std::string& bind_port);

        Server& operator=(const Server&) = delete;
        Server& operator=(const Server&&);

        int listen();
}; //}

/**
 * @class represent a socks5 connection */
class ClientConnection //{
{
    private:
        uv_tcp_t* mp_tcp;
        ConnectionProxy* m_connectionWrapper;
        uv_read_cb m_read_callback;


    public:
        ClientConnection(const sockaddr* addr, ConnectionProxy* p, uv_read_cb cb);

        ClientConnection(const ClientConnection&) = delete;
        inline ClientConnection(ClientConnection&& a) {
            *this = static_cast<ClientConnection&&>(a);
        }

        ClientConnection& operator=(ClientConnection&) = delete;
        ClientConnection& operator=(ClientConnection&&);

    int write(uv_buf_t buf, uv_write_cb cb);
}; //}

/**
 * @class ConnectionProxy Multiplexing a single ssl/tls connection to multiple tcp connection */
class ConnectionProxy //{
{
    private:
        std::map<uint8_t, ClientProxy*> m_map;
        Server* m_server;
        uv_tcp_t* m_connection;

    public:
        ConnectionProxy(Server* server);

        ConnectionProxy(const ConnectionProxy&) = delete;
        inline ConnectionProxy(ConnectionProxy&& a) {
            *this = static_cast<ConnectionProxy&&>(a);
        };

        ConnectionProxy& operator=(ConnectionProxy&&);
        ConnectionProxy& operator=(const ConnectionProxy&) = delete;

        /**
         * @param addr network address
         * @return return 0 means everything is ok, otherwise error occurs
         */
        int new_connection(sockaddr* addr);

        int release_connection(uint8_t);

        void server_handshake();
        void user_authenticate();

        inline size_t getConnectionNumbers() {return this->m_map.size();}
}; //}

}

