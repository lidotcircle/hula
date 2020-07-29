#pragma once


#include "kclient_manager.h"
#include <uv.h>


NS_PROXY_CLIENT_START


class ServerManagerUV: public ServerManager {
    private:
        uv_loop_t* m_loop;
        std::string m_config_file;


    protected:
        HttpFileServer*  createHttpFileServer(const std::string& filename, UNST connection) override;
        WebSocketServer* createWSSession     (UNST connection) override;

        Server* createServer(const std::string& filename, UNST con) override;


    public:
        ServerManagerUV(const std::string& http_conf_file, uv_loop_t* loop);
        void start() override;
};


NS_PROXY_CLIENT_END

