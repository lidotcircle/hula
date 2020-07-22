#pragma once


#include <evtls/stream_tls.h>
#include "stream_libuv.h"


class EBStreamUVTLS: public EBStreamTLS
{
    protected:
        EBStreamObject* getStreamObject(UNST stream) override;


    public:
        EBStreamUVTLS(UNST stream, TLSMode mode, const std::string& cert, const std::string& privateKey);
        EBStreamUVTLS(uv_tcp_t* stream, TLSMode mode, const std::string& cert, const std::string& privateKey);
        EBStreamUVTLS(UNST stream);
        StreamType getType() override;
};

