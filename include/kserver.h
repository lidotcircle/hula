#pragma once

#include <uv.h>
#include <openssl/crypto.h>

#include <string>
#include <vector>
#include <tuple>
#include <map>
#include <set>
#include <unordered_set>

#include "events.h"
#include "utils.h"
#include "kpacket.h"
#include "config_file.h"
#include "config.h"
#include "object_manager.h"

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

namespace UVC {class UVCBaseServer;}

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
class Server: public EventEmitter, public ObjectManager //{
{
    public:
        struct connectionArgv: public EventArgs::Base {
            Server*   m_this;
            uv_tcp_t* m_new_connection;
            inline connectionArgv(Server* _this, uv_tcp_t* new_con): 
                m_this(_this), m_new_connection(new_con){}
        };

    private:
        uint32_t bind_addr;
        uint16_t bind_port;

        // uv data structures
        uv_loop_t* mp_uv_loop;
        uv_tcp_t*  mp_uv_tcp;

        ServerConfig* mp_config;

        std::unordered_set<ClientConnectionProxy*> m_tsl_list;

        static void on_connection(uv_stream_t* stream, int status);

        void dispatch_new_connection(uv_tcp_t* stream);

        static void on_config_load(int error, void* data);
        int __listen();

    protected:
        friend class ClientConnectionProxy;

        void remove_proxy(ClientConnectionProxy* p);

    public:
        Server(uv_loop_t* loop, const std::string& config_file);

        Server(const Server&) = delete;
        Server(Server&& s) = delete;
        Server& operator=(const Server&) = delete;
        Server& operator=(Server&&) = delete;

        int listen();
        void close();

        ~Server();

        inline bool HasConnection() {return this->m_tsl_list.size() != 0;}
}; //}


/**
 * @class ClientConnectionProxy Multiplexing a single ssl/tls connection to multiple tcp connection */
class ClientConnectionProxy: public EventEmitter //{
{
    public:
        using WriteCallback = void (*)(bool should_run, int status, ROBuf* buf, void* data);

    private:
        std::map<uint8_t, ServerToNetConnection*> m_map;
        std::set<uint8_t> m_wait_connect;
        Server* mp_server;
        uv_loop_t* mp_loop;

        uv_tcp_t* mp_connection;
        bool m_connection_read;

        size_t m_user_to_net_buffer = 0;
        size_t m_net_to_user_buffer = 0;

        ROBuf m_remains;

        enum __State {
            INIT = 0,
            TSL_HAND_SHAKE,
            USER_AUTHENTICATION,
            BUILD,
            ERROR,
            CLOSING,
            CLOSED
        };
        __State m_state;

        static void malloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* out);
        static void user_read_cb (uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
        static void user_stream_write_cb(uv_write_t*  write,  int status);

        void dispatch_new_encrypted_data  (ROBuf buf);
        void dispatch_new_unencrypted_data(ROBuf buf);
        void dispatch_authentication_data(ROBuf buf);
        void dispatch_packet_data(ROBuf buf);

        void dispatch_reg  (uint8_t id, ROBuf buf);  // OPCODE PACKET_OP_REG
        void dispatch_new  (uint8_t id, ROBuf buf);  // OPCODE PACKET_OP_NEW
        void dispatch_close(uint8_t id, ROBuf buf);  // OPCODE PACKET_OP_CLOSE

        void server_tsl_handshake();
        void user_authenticate();
        void start_relay();

        int _write(ROBuf buf, WriteCallback cb, void* data);


    public:
        ClientConnectionProxy(Server* server, uv_tcp_t* connection);

        ClientConnectionProxy(const ClientConnectionProxy&) = delete;
        ClientConnectionProxy(ClientConnectionProxy&& a) = delete;
        ClientConnectionProxy& operator=(ClientConnectionProxy&&) = delete;
        ClientConnectionProxy& operator=(const ClientConnectionProxy&) = delete;

        int close_connection (uint8_t id);
        int accept_connection(uint8_t id);
        int reject_connection(uint8_t id, NEW_CONNECTION_REPLY reason);

        void remove_connection(uint8_t id, ServerToNetConnection* con);

        void close();

        int write(uint8_t id, ROBuf buf, WriteCallback cb, void* data);

        inline size_t getConnectionNumbers() {return this->m_map.size();}
}; //}


/**
 * @class ServerToNetConnection Proxy a single tcp connection. When new packet arrives, relay the packet to client */
class ServerToNetConnection: public EventEmitter //{
{
    public:
        using data_callback = void (*)(ServerToNetConnection* con, uint8_t id, ROBuf buf);

    protected:
        using WriteCallback = void (*)(bool should_run, int status, ROBuf* buf, void* data);

    private:
        uv_loop_t* mp_loop;

        uv_tcp_t* mp_tcp;
        bool m_net_tcp_start_read;

        bool m_inform_client_stop_read = false;

        ClientConnectionProxy* mp_proxy;
        Server* mp_server;
        ConnectionId m_id;

        size_t m_net_to_user_buffer;
        size_t m_user_to_net_buffer;

        std::string m_addr;
        uint16_t m_port;

        void __connect();
        static void tcp2net_getaddrinfo_callback(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
        void __connect_with_sockaddr(sockaddr* addr);
        static void tcp2net_connect_callback(uv_connect_t* req, int status);
        static void tcp2net_alloc_callback  (uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
        static void tcp2net_read_callback   (uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
        static void tcp2net_write_callback  (uv_write_t* req, int status); // write buffer to net_tpc_connection

        void __start_net_to_user();
        void _write_to_user(ROBuf buf);
        static void _write_to_user_callback(bool should_run, int status, ROBuf* buf, void* data);


    public:
        ServerToNetConnection(Server* server, ClientConnectionProxy* proxy, uv_loop_t* loop, 
                              ConnectionId id, const std::string& addr, uint16_t port);

        ServerToNetConnection(const ServerToNetConnection&) = delete;
        ServerToNetConnection(ServerToNetConnection&& a) = delete;
        ServerToNetConnection& operator=(const ServerToNetConnection&) = delete;
        ServerToNetConnection& operator=(ServerToNetConnection&&) = delete;

        void PushData(ROBuf buf);
        void close();

        ~ServerToNetConnection();
}; //}

}

