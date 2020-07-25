#pragma once

#include "http_file_server.h"
#include "stream_libuvTLS.h"


class UVTLSHttpFileServer: public HttpFileServer, public EBStreamUVTLS {
    private:
        uv_loop_t* mp_loop;

    protected:
        Http*            createHttpSession(UNST con) override;
        FileAbstraction* createFile(const std::string& filename) override;

    public:
        UVTLSHttpFileServer(std::shared_ptr<HttpFileServerConfig> config, UNST tlscon);
        UVTLSHttpFileServer(std::shared_ptr<HttpFileServerConfig> config, uv_tcp_t* tcp, 
                            const std::string& cert, const std::string& privateKey);
};

