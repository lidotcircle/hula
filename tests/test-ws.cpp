#include "../include/websocket_libuv.h"

void echo_textMessage(EventEmitter* server, const std::string& event, EventArgs::Base* argv) {
    UVWebsocketCommon* _this = dynamic_cast<decltype(_this)>(server);
    assert(_this);
    WSEventTextMessage* _msg = dynamic_cast<decltype(_msg)>(argv);
    assert(_msg);
    std::cout << "textMessage: " << _msg->m_msg << std::endl;
    delete _msg;
}

void on_end(EventEmitter* obj, const std::string& event, EventArgs::Base* argv) {
    std::cout << "end" << std::endl;
    delete obj;
    delete argv;
}

void echo_message(EventEmitter* server, const std::string& event, EventArgs::Base* argv) {
    UVWebsocketCommon* _this = dynamic_cast<decltype(_this)>(server);
    assert(_this);
    WSEventMessage* _msg = dynamic_cast<decltype(_msg)>(argv);
    assert(_msg);
    std::cout << "message: " << _msg->m_msg << std::endl;
    delete _msg;
}

void echo_fragment(EventEmitter* server, const std::string& event, EventArgs::Base* argv) {
    UVWebsocketCommon* _this = dynamic_cast<decltype(_this)>(server);
    assert(_this);
    WSEventFragment* _msg = dynamic_cast<decltype(_msg)>(argv);
    assert(_msg);
    std::cout << "fragment: " << _msg->m_buf << std::endl;
    delete _msg;
}

void uv_connection_callback(uv_stream_t* stream, int status) {
    std::cout << "new connection" << std::endl;
    uv_tcp_t* accept = new uv_tcp_t();
    uv_tcp_init(uv_handle_get_loop((uv_handle_t*)stream), accept);
    if(uv_accept(stream, (uv_stream_t*)accept) < 0) {
        std::cout << "something wrong" << std::endl;
        uv_close((uv_handle_t*)accept, nullptr);
        delete accept;
        return;
    };
    UVWebsocketServer* server = new UVWebsocketServer(accept);
    server->on("textMessage", echo_textMessage);
    server->on("message", echo_message);
    server->on("fragment", echo_fragment);
    server->on("end", on_end);
    server->sendText("hello client!");
    server->end(WebsocketStatusCode::CLOSE_NORMAL, "no reason xx");
}

void start_ws_server(uv_loop_t* loop) {
    uv_tcp_t* tcp = new uv_tcp_t();
    uv_tcp_init(loop, tcp);
    sockaddr_in addr;
    uv_ip4_addr("0.0.0.0", 8877, &addr);
    uv_tcp_bind(tcp, (sockaddr*)&addr, 0);
    uv_listen((uv_stream_t*)tcp, 100, uv_connection_callback);
    std::cout << "listen at: 0.0.0.0:8877" << std::endl;
}

void uv_connect_callback(uv_connect_t* req, int status) {
    std::cout << "connect to $$ with: " << status << std::endl;
    uv_tcp_t* tcp = static_cast<decltype(tcp)>(uv_req_get_data((uv_req_t*)req));
    delete req;
    UVWebsocketClient* client = new UVWebsocketClient(tcp);
    client->on("textMessage", echo_textMessage);
    client->on("message", echo_message);
    client->on("fragment", echo_fragment);
    client->on("end", on_end);
    client->sendText("hello server!");
    client->send(ROBuf((char*)std::string("hello nilegejier").c_str(), 17));
    client->end(WebsocketStatusCode::CLOSE_NORMAL, "no reason");
}

void connect_to(uv_loop_t* loop) {
    uv_tcp_t* tcp = new uv_tcp_t();
    uv_tcp_init(loop, tcp);
    sockaddr_in addr;
    uv_ip4_addr("127.0.0.1", 8877, &addr);
    uv_connect_t* req = new uv_connect_t();
    uv_req_set_data((uv_req_t*)req, tcp);
    uv_tcp_connect(req, tcp, (sockaddr*)&addr, uv_connect_callback);
}

int main() {
    uv_loop_t loop;
    uv_loop_init(&loop);

    start_ws_server(&loop);
    connect_to(&loop);
    uv_run(&loop, UV_RUN_DEFAULT);

    uv_loop_close(&loop);
    return 0;
}

