#include "../include/stream_object_libuvTLS.h"
#include "../include/stream_object_libuv.h"
#include "../include/utils.h"
#include "../include/libuv_utils.h"
#include "../include/config.h"
#include <uv.h>
#include <string>
#include <iostream>

#include "cert.h"


static bool uv_continue = true;
static bool uv_timer_set = false;
static int handle_count = 0;
static uv_loop_t* g_loop = nullptr;
static bool close_loop = true;
static EBStreamObject* stream_server = nullptr;
static EBStreamObject* stream_client = nullptr;
static EBStreamObject* stream_accept = nullptr;

void close_global_loop_atexit() {if(!close_loop) uv_loop_close(g_loop); close_loop = true;}

void error_listener_1(EventEmitter* obj, const std::string&, EventArgs::Base*) //{
{
    std::cout << "server accept error ???" << std::endl;
    delete stream_accept;
    stream_accept = nullptr;
    return;
} //}
void error_listener_2(EventEmitter* obj, const std::string&, EventArgs::Base*) //{
{
    std::cout << "client error??? ???" << std::endl;
    delete stream_client;
    stream_client = nullptr;
    return;
} //}
void error_listener_3(EventEmitter* obj, const std::string&, EventArgs::Base*) //{
{
    std::cout << "server error ???" << std::endl;
    delete stream_server;
    stream_server = nullptr;
    return;
} //}
void data_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    std::cout << "on_data" << std::endl;
    EBStreamObject::DataArgs* args = dynamic_cast<decltype(args)>(aaa); assert(args);
    EBStreamObject* _this = dynamic_cast<decltype(_this)>(obj); assert(_this);
    std::cout << args->_buf << std::endl;
    _this->write(args->_buf);
} //}
void connection_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    std::cout << "on_connection" << std::endl;
    EBStreamObject::ConnectionArgs* args = dynamic_cast<decltype(args)>(aaa); assert(args);
    EBStreamObject* _this = dynamic_cast<decltype(_this)>(obj); assert(_this);
    auto streamx = _this->NewStreamObject(args->connection);
    stream_accept = streamx;
    streamx->on("error", error_listener_1);
    streamx->on("data", data_listener);
    streamx->on("end", error_listener_1);
    streamx->startRead();
} //}
void test1_a() //{
{
    uv_tcp_t* tcp = new uv_tcp_t();
    uv_tcp_init(g_loop, tcp);
    EBStreamObject* obj = new StreamObjectUVTLS(1, EBStreamUVTLS::TLSMode::ServerMode, tcp, certificate, privateKey);
    //EBStreamObject* obj = new EBStreamObjectUV(tcp, 1);

    stream_server = obj;
    obj->on("error", error_listener_3);
    obj->on("data", data_listener);
    obj->on("connection", connection_listener);

    uint32_t ip4 = 0;
    assert(str_to_ip4("0.0.0.0", &ip4));
    obj->bind_ipv4(8800, k_ntohl(ip4));
    obj->listen();
//    obj->emit("error", new EBStreamObject::ErrorArgs("error"));
} //}

void connect_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    std::cout << "on_connect" << std::endl;
    EBStreamObject* stream = dynamic_cast<decltype(stream)>(obj); assert(stream);
    stream->startRead();
    stream->write(SharedMem((char*)"hello world", 11));
} //}
void test1_b() //{
{
    uv_tcp_t* tcp = new uv_tcp_t();
    uv_tcp_init(g_loop, tcp);
    EBStreamObject* obj = new StreamObjectUVTLS(1, EBStreamUVTLS::TLSMode::ClientMode, tcp, certificate, privateKey);
    //EBStreamObject* obj = new EBStreamObjectUV(tcp, 1);

    stream_client = obj;
    obj->on("error", error_listener_2);
    obj->on("data", data_listener);
    obj->on("connect", connect_listener);

    obj->connectTo("localhost", 8800);
} //}

static void timer_handle(uv_timer_t* timer) //{
{
    uv_timer_stop(timer);
    uv_close((uv_handle_t*)timer, UVU::delete_closed_handle<decltype(timer)>);
    uv_timer_set = false;
} //}
#define STDOUT_HANDLE(h) \
    case h: std::cout << #h; break

static void walk_callback(uv_handle_t* h, void* data) //{
{
    ++handle_count;
    auto type = uv_handle_get_type(h);
    std::cout << "    handle: " << handle_count << ", type: ";
    switch(type) {
        STDOUT_HANDLE(UV_CHECK);
        STDOUT_HANDLE(UV_FILE);
        STDOUT_HANDLE(UV_HANDLE);
        STDOUT_HANDLE(UV_ASYNC);
        STDOUT_HANDLE(UV_POLL);
        STDOUT_HANDLE(UV_IDLE);
        STDOUT_HANDLE(UV_FS_EVENT);
        STDOUT_HANDLE(UV_FS_POLL);
        STDOUT_HANDLE(UV_PREPARE);
        STDOUT_HANDLE(UV_PROCESS);
        STDOUT_HANDLE(UV_NAMED_PIPE);
        STDOUT_HANDLE(UV_STREAM);
        STDOUT_HANDLE(UV_TCP);
        STDOUT_HANDLE(UV_UDP);
        STDOUT_HANDLE(UV_TIMER);
        STDOUT_HANDLE(UV_TTY);
        STDOUT_HANDLE(UV_SIGNAL);
        STDOUT_HANDLE(UV_UNKNOWN_HANDLE);
        STDOUT_HANDLE(UV_HANDLE_TYPE_MAX);
    }
    std::cout << std::endl;
} //}
static void walk_loop(uv_loop_t* loop) //{
{
    handle_count = 0;
    uv_walk(loop, walk_callback, nullptr);
} //}
static void interrupt_handle(int sig) //{
{
    if(uv_continue == false) {
        walk_loop(g_loop);
        exit(1);
    }
    __logger->warn("Exiting ...");
    uv_continue = false;
    if(stream_server) stream_server->emit("error", new EBStreamObject::ErrorArgs("error"));
    if(stream_client) stream_client->emit("error", new EBStreamObject::ErrorArgs("error"));
    if(stream_accept) stream_accept->emit("error", new EBStreamObject::ErrorArgs("error"));
} //}

int main() //{
{
    //__logger->Level = Logger::LoggerLevel::LOGGER_INFO;
    //Logger::logger->disable();

    uv_loop_t loop;
    uv_loop_init(&loop);
    g_loop = &loop;
    close_loop = false;
    atexit(close_global_loop_atexit);

    signal(SIGINT,  interrupt_handle);
    struct sigaction mm = {SIG_IGN};
    sigaction(SIGPIPE, &mm, nullptr);

    test1_a();
    test1_b();

    while(uv_continue) {
        if(uv_timer_set == false) {
            uv_timer_t* timer = new uv_timer_t();
            uv_timer_init(&loop, timer);
            uv_timer_start(timer, timer_handle, 1000, 0);
            uv_timer_set = true;
        }
        uv_run(&loop, UV_RUN_ONCE);
    }

    while(uv_loop_alive(&loop)) uv_run(&loop, UV_RUN_ONCE);

    uv_loop_close(&loop);
    close_loop = true;
    return 0;
} //}

