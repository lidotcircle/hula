#pragma once

#include "kserver.h"
#include "stream.h"

#include <memory>
#include <unordered_set>

NS_PROXY_SERVER_START

/**
 * Server provides methods to listen at specific tcp address and 
 * to handle incoming connection. Each object of this class own a tcp
 * socket of uv(sole owner), and belong to an uv event loop. 
 *
 * @event connection @fires when new conection is accepted
 *        (uv_tcp_t* accept_stream, Server* this_server)
 */
class Server: virtual protected EBStreamAbstraction //{
{
    private:
        uint32_t bind_addr;
        uint16_t bind_port;

        std::shared_ptr<ServerConfig> m_config;

        std::unordered_set<ConnectionProxyAbstraction*> m_connection_list;


    protected:
        friend class ClientConnectionProxy;

        void remove_proxy(ConnectionProxyAbstraction* p);

        void read_callback(ROBuf buf, int status) override;
        void on_connection(UNST connection) override;

    public:
        Server(std::shared_ptr<ServerConfig> config);

        Server(const Server&) = delete;
        Server(Server&& s) = delete;
        Server& operator=(const Server&) = delete;
        Server& operator=(Server&&) = delete;

        int  trylisten();
        void close();

        ~Server();

        inline bool HasConnection() {return this->m_connection_list.size() != 0;}
}; //}

NS_PROXY_SERVER_END
