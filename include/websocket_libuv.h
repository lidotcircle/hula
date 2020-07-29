#pragma once

#include "websocket.h"
#include "stream_libuv.h"

#include <set>

class UVWebsocketClient: public WebSocketClient, public EBStreamUV //{
{
    public:
        UVWebsocketClient(uv_tcp_t* connection, bool save_fragment = false);
}; //}
class UVWebsocketServer: public WebSocketServer, public EBStreamUV //{
{
    public:
        UVWebsocketServer(uv_tcp_t* connection, bool save_fragment = false);
}; //}


