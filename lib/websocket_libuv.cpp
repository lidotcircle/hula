#include "../include/websocket_libuv.h"


UVWebsocketClient::UVWebsocketClient(uv_tcp_t* connection, bool save_fragment):
    WebSocketClient(save_fragment), EBStreamUV(connection) {this->start_read();}

UVWebsocketServer::UVWebsocketServer(uv_tcp_t* connection, bool save_fragment):
    WebSocketServer(save_fragment), EBStreamUV(connection) {this->start_read();}

