#pragma once

#include <uv.h>
#include <openssl/crypto.h>

#include <string>
#include <vector>
#include <tuple>
#include <map>

#include "events.h"
#include "utils.h"
#include "kpacket.h"
#include "dlinkedlist.hpp"
#include "config_file.h"

#define DEFAULT_BACKLOG 100

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
 *
 * @event connection @fires when new conection is accepted
 *        (uv_tcp_t* accept_stream, Server* this_server)
 */
class Server: public EventEmitter //{
{
    public:
        using connectionType = std::tuple<uv_tcp_t*>;

    private:
        uint32_t bind_addr;
        uint16_t bind_port;

        // uv data structures
        uv_loop_t* mp_uv_loop;
        uv_tcp_t*  mp_uv_tcp;

        ServerConfig* config;

        DLinkedList<ClientConnectionProxy*>* tsl_list;

        static void on_connection(uv_stream_t* stream, int status);

        void dispatch_new_connection(uv_tcp_t* stream);

        static void on_config_load(int error, void* data);
        int __listen();

    public:
        Server(uv_loop_t* loop, const std::string& config_file);

        Server(const Server&) = delete;
        Server(Server&& s) = delete;
        Server& operator=(const Server&) = delete;
        Server& operator=(Server&&) = delete;

        int listen();
        int close();
}; //}


/**
 * @class ServerToNetConnection Proxy a single tcp connection. When new packet arrives, relay the packet to client */
class ServerToNetConnection: public EventEmitter //{
{
    public:
        using data_callback = void (*)(ServerToNetConnection* con, uint8_t id, ROBuf buf);

    private:
        uv_loop_t* mp_loop;
        uv_tcp_t* mp_tcp;
        ClientConnectionProxy* m_connectionWrapper;
        size_t used_buffer_size;
        ConnectionId id;

        using write_callback = void (*)(void*);

        static void tcp_read_callback   (uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
        static void tcp_connect_callback(uv_connect_t* req, int status);
        static void tcp_alloc_callback  (uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
        static void tcp_write_callback  (uv_write_t* req, int status);

        /** wrapper of uv_write() */
        int _write(uv_buf_t bufs[], unsigned int nbufs, write_callback cb, void* arg);

    public:
        ServerToNetConnection(uv_loop_t* loop, const sockaddr* addr, ConnectionId id, ClientConnectionProxy* p);

        ServerToNetConnection(const ServerToNetConnection&) = delete;
        ServerToNetConnection(ServerToNetConnection&& a) = delete;
        ServerToNetConnection& operator=(const ServerToNetConnection&) = delete;
        ServerToNetConnection& operator=(ServerToNetConnection&&) = delete;

        /* 
         * @return indicate congestion state, #return < 0 means connection is congested. */
        int write(ROBuf buf);

        int realy_back(uv_buf_t buf);

        inline bool readable() const {return this->mp_tcp != nullptr && uv_is_readable((uv_stream_t*)this->mp_tcp);}
        inline bool writable() const {return this->mp_tcp != nullptr && uv_is_writable((uv_stream_t*)this->mp_tcp);}

        void close();

        ~ServerToNetConnection();
}; //}


/**
 * @class ClientConnectionProxy Multiplexing a single ssl/tls connection to multiple tcp connection */
class ClientConnectionProxy: public EventEmitter //{
{
    public:
        using write_callback = void (*)(ClientConnectionProxy* proxy, uint8_t id, uv_buf_t*, int status);

    private:
        std::map<uint8_t, ServerToNetConnection*> m_map;
        Server* m_server;
        uv_loop_t* mp_loop;
        uv_tcp_t* m_connection;
        DLinkedList<ClientConnectionProxy*>* m_entry;

        ROBuf remains = ROBuf();

        static void malloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* out);
        static void read_cb  (uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
        static void write_cb (uv_write_t*  write,  int status);

        static void query_dns_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res);

        void query_dns_connection(char* addr, uint16_t port, uint8_t id);

        void dispatch_new_encrypted_data  (ssize_t nread, ROBuf buf);
        void dispatch_new_unencrypted_data(ssize_t nread, ROBuf buf);

        void dispatch_reg  (uint8_t id, ROBuf buf);  // OPCODE PACKET_OP_REG
        void dispatch_new  (uint8_t id, ROBuf buf);  // OPCODE PACKET_OP_NEW
        void dispatch_close(uint8_t id, ROBuf buf);  // OPCODE PACKET_OP_CLOSE

        void to_internet_ipv4_connection(const sockaddr_in* addr, uint8_t id);

        void write_encrypted(uint8_t id, const uv_buf_t* buf, write_callback cb);

    public:
        ClientConnectionProxy(Server* server, uv_tcp_t* connection, DLinkedList<ClientConnectionProxy*>* list_entry);

        ClientConnectionProxy(const ClientConnectionProxy&) = delete;
        ClientConnectionProxy(ClientConnectionProxy&& a) = delete;
        ClientConnectionProxy& operator=(ClientConnectionProxy&&) = delete;
        ClientConnectionProxy& operator=(const ClientConnectionProxy&) = delete;

        /**
         * @param addr network address
         * @return return 0 means everything is ok, otherwise error occurs
         */
        int new_connection(sockaddr* addr);

        int release_connection(uint8_t);

        void server_tsl_handshake();
        void user_authenticate();

        int close();

        void write(PacketOp opcode, uint8_t id, const uv_buf_t* buf, write_callback cb);

        inline size_t getConnectionNumbers() {return this->m_map.size();}
}; //}

}

