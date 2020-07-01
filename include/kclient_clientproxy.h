#pragma once

#include "kclient.h"

NS_PROXY_CLIENT_START

/**
 * @class represent a socks5 connection */
class ClientConnection: public ClientProxyAbstraction //{
{
    public:
        struct __proxyWriteInfo {ClientConnection* _this; bool exited;};

    private:
        ConnectionProxy* mp_proxy;

        bool m_client_start_read;

        Server* mp_kserver;
        uint8_t m_id;

        Socks5ServerAbstraction* m_socks5;

        std::string m_server;
        uint16_t    m_port;

        enum __State {
            INITIAL = 0,
            CONNECTING,
            RUNNING,
            ERROR
        };
        __State m_state;
//        std::unordered_set<__proxyWriteInfo*> m_proxy_write_callbacks;

        size_t      m_in_buffer_size;
        size_t      m_out_buffer_size;

        void __start_relay();
        static void ProxyWriteCallback(bool should_run, int status, ROBuf* buf, void* data);

        static void write_to_client_callback(uv_write_t* req, int status);

        static void connect_callback(bool should_run, int status, void* data);
        void __connect(Socks5ServerAbstraction* socks5);

    protected:
        void read_callback(ROBuf buf, int status) override;

    public:
        ClientConnection(Server* kserver, ConnectionProxy* mproxy, 
                         const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5);

        ClientConnection(const ClientConnection&) = delete;
        ClientConnection(ClientConnection&& a) = delete; 
        ClientConnection& operator=(ClientConnection&) = delete;
        ClientConnection& operator=(ClientConnection&&) = delete;

        void run(Socks5ServerAbstraction* socks5);
        void PushData(ROBuf buf);
        void connect(Socks5ServerAbstraction* socks5);
        void close() override;

        void reject();
        void accept();

//        inline void SetSocks5NULL() {assert(this->m_socks5 != nullptr); this->m_socks5 = nullptr;}

        inline bool IsRun() {return this->m_state == __State::RUNNING;}
}; //}

NS_PROXY_CLIENT_END
