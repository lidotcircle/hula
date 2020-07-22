#pragma once

#include "StreamObject.h"
#include "stream.h"
#include "stream_libuv.h"
#include "object_manager.h"
#include "robuf.h"

#include <uv.h>


class EBStreamObjectUV: protected EBStreamUV, public EBStreamObject //{
{
    public:
        inline EBStreamObjectUV(uv_tcp_t* connection, size_t max): 
            EBStreamUV(connection), EBStreamObject(max) {}
        inline EBStreamObjectUV(UNST connection, size_t max): 
            EBStreamUV(connection), EBStreamObject(max) {}

        EBStreamObject* NewStreamObject(UNST stream) override;
        bool accept(EBStreamObject*) override;
}; //}

