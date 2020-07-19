#pragma once

#include "kclient.h"
#include "kclient_server.h"

#include <memory>


NS_PROXY_CLIENT_START

/**
 * @class Socks5Auth */
class Socks5Auth: public Socks5ServerAbstraction, virtual protected EBStreamAbstraction, virtual protected CallbackManager  //{
{
    private:
        enum SOCKS5_STAGE {
            SOCKS5_ERROR = 0,
            SOCKS5_INIT,
            SOCKS5_ID,
            SOCKS5_METHOD,
            SOCKS5_FINISH
        };
        SOCKS5_STAGE  m_state;

        std::shared_ptr<ClientConfig> m_config;
        Server*       mp_server;
        ROBuf         m_remain;

        std::string   m_servername;
        uint16_t      m_port;

        void dispatch_data(ROBuf buf);

        static void write_callback_hello(ROBuf buf, int status, void* data);
        static void write_callback_id   (ROBuf buf, int status, void* data);
        static void write_callback_reply(ROBuf buf, int status, void* data);

        void return_to_server();
        void close_this_with_error();
        void try_to_build_connection();

        void __send_selection_method(socks5_authentication_method method);
        void __send_auth_status(uint8_t status);
        void __send_reply(uint8_t reply);


    protected:
        void read_callback(ROBuf buf, int status) override;
        void end_signal() override;


    public:
        Socks5Auth(Server* server, std::shared_ptr<ClientConfig> config);
        ~Socks5Auth();

        void netAccept() override;
        void netReject() override;
        void start() override;
        EBStreamAbstraction::UNST transferStream() override;

        void close() override;
}; //}


NS_PROXY_CLIENT_END

