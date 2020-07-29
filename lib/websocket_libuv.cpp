#include "../include/websocket_libuv.h"


UVWebsocketClient::UVWebsocketClient(uv_tcp_t* connection, bool save_fragment):
    WebSocketClient(save_fragment), EBStreamUV(connection) {}

UVWebsocketServer::UVWebsocketServer(uv_tcp_t* connection, bool save_fragment):
    WebSocketServer(save_fragment), EBStreamUV(connection) {}

