#pragma once

#include "http_file_server.h"
#include "stream_libuv.h"


class UVHttpFileServer: public HttpFileServer, public EBStreamUV {
    private:
        uv_loop_t* mp_loop;

    protected:
        Http*            createHttpSession(UNST con) override;
        FileAbstraction* createFile(const std::string& filename) override;

    public:
        UVHttpFileServer(std::shared_ptr<HttpFileServerConfig> config, uv_tcp_t* tcp);
};

