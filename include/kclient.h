#pragma once

#include <uv.h>

#include <string>
#include <vector>
#include <tuple>
#include <map>

#include "../include/robuf.h"
#include "../include/utils.h"
#include "../include/events.h"

namespace KProxyClient {

class Server;
class ConnectionProxy;
class ClientProxy;

enum ConnectionState {
    CONNECTION_INIT = 0,
    CONNECTION_OPEN,
    CONNECTION_CLOSING,
    CONNECTION_CLOSED
};

/**
 * @class Server a socks5 proxy server */
class Server: EventEmitter //{
{
    private:
        uint32_t bind_addr;
        uint16_t bind_port;

        // uv data structures
        uv_loop_t* mp_uv_loop;
        uv_tcp_t*  mp_uv_tcp;

        void init_this(uv_loop_t* p_loop, uv_tcp_t* p_tcp, uint32_t a, uint16_t p);

        ConnectionState m_state;

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
        void close();
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

}

