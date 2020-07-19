#pragma once

#include "websocket.h"
#include "stream_libuv.h"

#include <set>

class UVWebsocketCommon: public EBStreamUV, public WebSocketCommon //{
{
    public:
        inline UVWebsocketCommon(uv_tcp_t* tcp_connection, bool masked, bool save_fragment): 
            EBStreamUV(tcp_connection), WebSocketCommon(masked, save_fragment) {};
}; //}

class UVWebsocketClient: public UVWebsocketCommon //{
{
    public:
        UVWebsocketClient(uv_tcp_t* connection, bool save_fragment = false);
}; //}
class UVWebsocketServer: public UVWebsocketCommon //{
{
    public:
        UVWebsocketServer(uv_tcp_t* connection, bool save_fragment = false);
}; //}


