#pragma once

#include "stream.hpp"
#include "config_file.h"
#include "kclient.h"

NS_PROXY_CLIENT_START


/**
 * @class Server a socks5 proxy server */
class Server: virtual public EBStreamAbstraction //{
{
    private:
        bool m_closed;

        uint32_t bind_addr;
        uint16_t bind_port;

        std::shared_ptr<ClientConfig> m_config;

        std::unordered_map<Socks5ServerAbstraction*, Socks5RequestProxy*> m_auths;
        std::unordered_set<RelayAbstraction*> m_relay;
        std::unordered_set<ProxyMultiplexerAbstraction*> m_proxy;


    protected:
        void on_connection(void* connection) override;


    private:
        void dispatch_base_on_addr(const std::string&, uint16_t, Socks5ServerAbstraction* socks5);
        void dispatch_bypass(const std::string&, uint16_t, Socks5ServerAbstraction* socks5);
        void dispatch_proxy (const std::string&, uint16_t, Socks5ServerAbstraction* socks5);

        /** implement strategy for selecting remote server */
        SingleServerInfo* select_remote_serever();

    public:
        Server(const Server&) = delete;
        Server(Server&& s) = delete;
        Server& operator=(const Server&) = delete;
        Server& operator=(const Server&&) = delete;

        Server(std::shared_ptr<ClientConfig> config);

        int  trylisten();
        void close();

        /** delete object which allocated by this object */
        void remove_socks5(Socks5ServerAbstraction* socks5);
        void remove_relay(RelayAbstraction* relay);
        void remove_proxy(ProxyMultiplexerAbstraction* proxy);

        void dispatchSocks5(const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5);
        void socks5Transfer(Socks5ServerAbstraction* socks5);

        Socks5RequestProxy* getSock5ProxyObject(Socks5ServerAbstraction* socks5);

        ~Server();
}; //}


NS_PROXY_CLIENT_END
