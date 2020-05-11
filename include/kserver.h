#pragma once

#include <uv.h>
#include <openssl/crypto.h>

#include <string>
#include <vector>
#include <tuple>
#include <map>

#include "../include/utils.h"
#include "../include/kpacket.h"

/**                           DESIGN OVERVIEW                                     //{
 *
 *   CLIENT SIDE
 *                                                                             
 *                               OTHERS APPLICATIONS
 * --------------------------------------------------------------------------------------
 *           |               |                                     |            
 *           |               |                                     |            
 *           |               |                                     |            
 *           v               v     INCOME SOCKS5 PROXY             v            
 *           -------------------------------------------------------                                                                 
 *           ~                    |           |         |                      
 *           ~                    v           v         v                      
 *           ~             -----------------------------------
 *           ~             |               SOCKS5 PROXY      |
 *     RELAY ~             |    SERVER     Listen AT ...     |
 *           ~             |                                 |
 *           ~             ----------------------------------
 *           ~                    |                        |          ...
 *           ~                    |                        |          ...
 *     ----------               ----------------------       ----------------------
 *     | Client |    SETOF      |                    |       |                    |
 *     | Proxy  | <------------ |   ConnectionProxy  |       |   ConnectionProxy  | ....
 *     |        |               |                    |       |                    |
 *     | -TCP   |     --------->|                    |       |                    |
 *     ----------     |         ----------------------       ----------------------
 *                    |          |                   |                         
 *                    |          | TCP               |            ............ 
 *            SSL/TSL |          | REQUEST           |            ............ 
 *                    |          |                   |            ............ 
 *        Connection  |          |                   |                         
 *        Multiplexer |          |                   |                         
 *                    |          |                   |                         
 *   _________________|__________|___________________|_____________________________  NETWORK
 *                    |          |                   |                         
 *                    |          |                   |                         
 *                    |          |                   |                         
 *   SERVER SIDE      |          |                   |                                    
 *                    |          v                   v                         
 *                    |    -----------------------------------                                                                   
 *                    |    |                                 |                                                     
 *                    |    |    SERVER     Listen AT ...     |                                                           
 *                    |    |                                 |                                                     
 *                    |    -----------------------------------
 *                    |           |            |          ......                                  
 *                    v           |            |          ......                                  
 *         ----------------------------       ----------------------------           -----------------
 *         |                          |       |                          |   SETOF   | ServerTo      |
 *         |   ClientConnectionProxy  |       |   ClientConnectionProxy  |  -------> | NetConnection |
 *         |                          |       |                          |           | -TCP          |
 *         ----------------------------       ----------------------------           -----------------
 *                                                                                       ^
 *                                                                                       |
 *               .                                              .                        | PROXY TRAFFIC
 *               .                                              .                        |
 *               .                                              .                        v
 * --------------------------------------------------------------------------------------------------- INTERNET
 *                                                                             
 *///}


namespace KProxyServer {

class ClientConnectionProxy;
class ServerToNetConnection;

/**
 * @class Server provides methods to listen at specific tcp address and 
 *        to handle incoming connection. Each object of this class own a tcp
 *        socket of uv(sole owner), and belong to an uv event loop.
 */
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
 * @class ServerToNetConnection Proxy a single tcp connection. When new packet arrives, relay the packet to client
 */
class ServerToNetConnection //{
{
    private:
        uv_tcp_t* mp_tcp;
        ClientConnectionProxy* m_connectionWrapper;
        uv_read_cb m_read_callback;
        size_t used_buffer_size;
        ConnectionId id;

    public:
        ServerToNetConnection(const sockaddr* addr, ConnectionId id, ClientConnectionProxy* p, uv_read_cb cb);

        ServerToNetConnection(const ServerToNetConnection&) = delete;
        inline ServerToNetConnection(ServerToNetConnection&& a) {
            *this = static_cast<ServerToNetConnection&&>(a);
        }

        ServerToNetConnection& operator=(ServerToNetConnection&) = delete;
        ServerToNetConnection& operator=(ServerToNetConnection&&);

        /* wrapper of uv_write() */
        int write(uv_buf_t bufs[], unsigned int nbufs, uv_write_cb cb);

        int realy_back(uv_buf_t buf);

        inline bool readable() const {return this->mp_tcp != nullptr && uv_is_readable((uv_stream_t*)this->mp_tcp);}
        inline bool writable() const {return this->mp_tcp != nullptr && uv_is_writable((uv_stream_t*)this->mp_tcp);}

        ~ServerToNetConnection();
}; //}


/**
 * @class ClientConnectionProxy Multiplexing a single ssl/tls connection to multiple tcp connection
 */
class ClientConnectionProxy //{
{
    private:
        std::map<uint8_t, ServerToNetConnection*> m_map;
        Server* m_server;
        uv_tcp_t* m_connection;

    public:
        ClientConnectionProxy(Server* server);

        ClientConnectionProxy(const ClientConnectionProxy&) = delete;
        inline ClientConnectionProxy(ClientConnectionProxy&& a) {
            *this = static_cast<ClientConnectionProxy&&>(a);
        };

        ClientConnectionProxy& operator=(ClientConnectionProxy&&);
        ClientConnectionProxy& operator=(const ClientConnectionProxy&) = delete;

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

