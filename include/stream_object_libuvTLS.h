#pragma once

#include <evtls/stream_object.h>
#include "stream_libuvTLS.h"

class StreamObjectUVTLS: protected EBStreamUVTLS, public EBStreamObject
{
    public:
        using TLSMode = TLSMode;

    protected:
        using EBStreamObject::read_callback;

    public:
        StreamObjectUVTLS(size_t max_buffer_size, UNST stream);
        StreamObjectUVTLS(size_t max_buffer_size, TLSMode mode, UNST stream, const std::string& cert, const std::string& privateKey);
        StreamObjectUVTLS(size_t max_buffer_size, TLSMode mode, uv_tcp_t* stream, const std::string& cert, const std::string& privateKey);

        bool accept(EBStreamObject*) override;
        EBStreamObject* NewStreamObject(UNST stream) override;
};

