#include "../include/websocket_libuv.h"


UVWebsocketClient::UVWebsocketClient(uv_tcp_t* connection, bool save_fragment):
    UVWebsocketCommon(connection, true, save_fragment) {}

UVWebsocketServer::UVWebsocketServer(uv_tcp_t* connection, bool save_fragment):
    UVWebsocketCommon(connection, false, save_fragment) {}

