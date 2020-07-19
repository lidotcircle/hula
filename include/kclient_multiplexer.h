#pragma once
#include "stream.h"
#include "StreamProvider_KProxyMultiplexer.h"

#include "kclient.h"

NS_PROXY_CLIENT_START

/**
 * @class ConnectionProxy Multiplexing a single ssl/tls connection to multiple tcp connection */
class ConnectionProxy: public ProxyMultiplexerAbstraction, 
    virtual protected EBStreamAbstraction, protected KProxyMultiplexerStreamProvider //{
{
    public:
        using ConnectCallback = ProxyMultiplexerAbstraction::ConnectCallback;


   private:
        Server*    mp_server;
        SingleServerInfo* mp_server_info;

        set<ClientProxyAbstraction*> m_proxyrelays;

        ROBuf m_remain;

        enum __State {
            STATE_INITIAL = 0,
            STATE_CONNECTING,
            STATE_AUTH,
            STATE_WAIT_AUTH_REPLY,
            STATE_BUILD,
            STATE_CLOSING,
            STATE_CLOSED,
            STATE_ERROR
        };
        __State m_state;

        /** statistics */
        size_t m_total_write_to_client_buffer;
        size_t m_total_write_to_server_buffer;

        ConnectCallback m_connect_cb;
        void*           m_connect_cb_data;


    protected:
        void read_callback(ROBuf, int status) override;
        void end_signal() override;


    private:
        void __connectToServer(ConnectCallback cb, void* data);
        static void connect_to_remote_server_callback(int status, void* data);

        void send_authentication_info();
        static void on_authentication_write(ROBuf buf, int status, void* data);

        void authenticate(ROBuf buf);


    protected:
        void prm_error_handle() override;
        void prm_write(ROBuf buf, KProxyMultiplexerStreamProvider::WriteCallback cb, void* data) override;
        void prm_timeout(KProxyMultiplexerStreamProvider::TimeoutCallback cb, void* data, int ms) override;


   public:
        ConnectionProxy(Server* server, SingleServerInfo* server_info);

        ConnectionProxy(const ConnectionProxy&) = delete;
        ConnectionProxy(ConnectionProxy&& a) = delete;
        ConnectionProxy& operator=(ConnectionProxy&&);
        ConnectionProxy& operator=(const ConnectionProxy&) = delete;

        void connectToServer(ConnectCallback cb, void* data) override;
        void remove_clientConnection(ClientProxyAbstraction* obj) override;
        void register_clientConnection(ClientProxyAbstraction* obj) override;

        uint8_t getConnectionNumbers() override;
        bool    connected() override;
        bool    full() override;
        bool    uninit() override;

        KProxyMultiplexerStreamProvider* getProvider() override;

        void close() override;

        void CreateNewConnection(EBStreamObject* obj, StreamId, const std::string& addr, uint16_t port) override;
        void CreateConnectionSuccess(StreamId) override;
        void CreateConnectionFail   (StreamId, uint8_t reason) override;

        ~ConnectionProxy();
}; //}


NS_PROXY_CLIENT_END

