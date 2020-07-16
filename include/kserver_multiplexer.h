#pragma once

#include "kserver.h"
#include "kserver_server.h"
#include "stream.hpp"
#include "StreamProvider_KProxyMultiplexer.h"

NS_PROXY_SERVER_START

/**
 * @class ClientConnectionProxy Multiplexing a single ssl/tls connection to multiple tcp connection */
class ClientConnectionProxy: virtual public EBStreamAbstraction, public KProxyMultiplexerStreamProvider, 
    virtual private CallbackManager, public ConnectionProxyAbstraction //{
{
    private:
        std::set<ToNetAbstraction*> m_relays;
        Server* mp_server;

        ROBuf m_remains;

        bool in_authentication;
        void dispatch_authentication_data(ROBuf buf);


    protected:
        void read_callback(ROBuf buf, int status) override;
        void end_signal() override;

        void prm_error_handle() override;
        void prm_write(ROBuf buf, KProxyMultiplexerStreamProvider::WriteCallback cb, void* data) override;
        void prm_timeout(KProxyMultiplexerStreamProvider::TimeoutCallback cb, void* data, int ms) override;

        static void authentication_write_callback(ROBuf buf, int status, void* data);


    public:
        ClientConnectionProxy(Server* server);

        ClientConnectionProxy(const ClientConnectionProxy&) = delete;
        ClientConnectionProxy(ClientConnectionProxy&& a) = delete;
        ClientConnectionProxy& operator=(ClientConnectionProxy&&) = delete;
        ClientConnectionProxy& operator=(const ClientConnectionProxy&) = delete;

        void start() override;

        void CreateNewConnection(EBStreamObject* obj, StreamId, const std::string& addr, uint16_t port) override;

        void remove_connection(ToNetAbstraction* con) override;
        void close() override;
}; //}


NS_PROXY_SERVER_END

