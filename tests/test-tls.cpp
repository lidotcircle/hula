#include "../include/stream_object_libuvTLS.h"
#include "../include/stream_object_libuv.h"
#include "../include/utils.h"
#include "../include/libuv_utils.h"
#include "../include/config.h"
#include <uv.h>
#include <string>
#include <iostream>

static bool uv_continue = true;
static bool uv_timer_set = false;
static int handle_count = 0;
static uv_loop_t* g_loop = nullptr;
static bool close_loop = true;
static EBStreamObject* stream_server = nullptr;
static EBStreamObject* stream_client = nullptr;
static EBStreamObject* stream_accept = nullptr;

void close_global_loop_atexit() {if(!close_loop) uv_loop_close(g_loop); close_loop = true;}

const std::string certificate = //{
                "-----BEGIN CERTIFICATE-----\n"
                "MIIDfTCCAmUCFDHbl8DpsaE9xtJ2Xn8mpu+g3QQ0MA0GCSqGSIb3DQEBCwUAMHsx\n"
                "CzAJBgNVBAYTAkNOMQ8wDQYDVQQIDAZGdUppYW4xDzANBgNVBAcMBkZ1WmhvdTEL\n"
                "MAkGA1UECgwCR00xCzAJBgNVBAsMAkdNMQswCQYDVQQDDAJHTTEjMCEGCSqGSIb3\n"
                "DQEJARYUZmFrZWFkZHJlc3NAZmFrZS5jb20wHhcNMjAwNzIwMDY0MTA5WhcNMzAw\n"
                "NzE4MDY0MTA5WjB7MQswCQYDVQQGEwJDTjEPMA0GA1UECAwGRnVKaWFuMQ8wDQYD\n"
                "VQQHDAZGdVpob3UxCzAJBgNVBAoMAkdNMQswCQYDVQQLDAJHTTELMAkGA1UEAwwC\n"
                "R00xIzAhBgkqhkiG9w0BCQEWFGZha2VhZGRyZXNzQGZha2UuY29tMIIBIjANBgkq\n"
                "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuqSF08BCMv7pBYz+JObgJMRJ1Cf0xlNm\n"
                "Ag6L9NZ4Cu1Uy1TRrA6mOD/IFbuwXddMXLSvO2O8VlHfhXG/XKZPOaW5CI3sDfAQ\n"
                "SWhzyPeFkfuzsBpavV0ECO+8QmQ2d0mskC15lS0emeCAgwUC5XL1U5T9IgTlh5q+\n"
                "0WiYpPhiaZVXh/fk4+HQk2NCzaH8K5sme088y5rqmpYmYQtDakXMcXvgdFB7tGTy\n"
                "LlFX0Uy5EJkzyTAU96OoOtwhSyTdCSPxU3R30JmNm+vpvQjwYx/apQ1C+k596MoZ\n"
                "wMswuxTfBC6x6TtQyqzuJ6W1uIUDaCIURev90AmezMEi9+jYMae7ZQIDAQABMA0G\n"
                "CSqGSIb3DQEBCwUAA4IBAQBCTzDrfLNtlbOcSpQcb/t1v9wXN1rM9h61xaFVv/gd\n"
                "kqZhKvuJN+qZ46SoZ8PjcSOTmQz8WAPZ9XG//ripPk4STDih++P4AKWPuZduK9lf\n"
                "Bqd6liMfqXJCAGg3fDkvjQv9Jqj4TX7qDQmyR7Sa2VFv7ZHnPUqTizwORvd4zq/f\n"
                "yHpMI5qHV6M7g609s7b++xKhAp7IlPpVGyr1h+EkUM6fP74Yi1nKB7HwoeX7NFil\n"
                "CoBI+EO5pcWbhcj6Gj4caUbVYONYxUOGV84FxFnnze0wDLlxaxSy3NvqHCPtC2h9\n"
                "dpXpgL8achlcCEouYxeA+JLhP8yjmpefBzhcjh09qMWM\n"
                "-----END CERTIFICATE-----"; //}
const std::string privateKey  = //{
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "MIIEpAIBAAKCAQEAuqSF08BCMv7pBYz+JObgJMRJ1Cf0xlNmAg6L9NZ4Cu1Uy1TR\n"
                "rA6mOD/IFbuwXddMXLSvO2O8VlHfhXG/XKZPOaW5CI3sDfAQSWhzyPeFkfuzsBpa\n"
                "vV0ECO+8QmQ2d0mskC15lS0emeCAgwUC5XL1U5T9IgTlh5q+0WiYpPhiaZVXh/fk\n"
                "4+HQk2NCzaH8K5sme088y5rqmpYmYQtDakXMcXvgdFB7tGTyLlFX0Uy5EJkzyTAU\n"
                "96OoOtwhSyTdCSPxU3R30JmNm+vpvQjwYx/apQ1C+k596MoZwMswuxTfBC6x6TtQ\n"
                "yqzuJ6W1uIUDaCIURev90AmezMEi9+jYMae7ZQIDAQABAoIBAErG+bsxzxQBXzjT\n"
                "GUuNmIYCgpXWgFIpPbhbPaWVe7jdB1kDnZGyuNPWcgKLFQkz5itKVN6VgfKPkN81\n"
                "CHdFRn6RMAYGXmnjIZNXnvQIf2JSltZaaLpvlttBuYpb/hpi0RlertSepCEAelyD\n"
                "2Ho3SaT4D0be8VsYG5Vos6d8wGkONSVT2rFq1wTgvd5fO+WTObamQ4p/mjMozmnh\n"
                "KEEbHNhewErTnv7VqQWTkg0ZLYEfUk11T7+kkp2snhe0J5I4REa5CemVPbc6Y1q4\n"
                "wYgxEHEUOxJcfZbl1o2fLrktLqPmchy07r0Smz9nhCFBOOgZnRdHpGrTMxLq7fM0\n"
                "+MNGuIECgYEA9JmiK+yCzUGww0OeF5H5XVfZ5aVGhje3r7XTrzfTf2ZgcBX9CKCX\n"
                "rvaHOsmjBHQdrcPPIKPJ//Ha9rqjltBhYbfvdtbf5NsJfHdT9S0BQJQMHNHQGdCg\n"
                "zbgD6PCmUFTpiV3ZeMO0JPLZCiZLyuUUAQbQgYyEU6lzTbjkdES4tMUCgYEAw1dj\n"
                "hKzyJIUXN0XLhGGjRkwz8mDYsJpB593pEAbGDVLok98clthIYls+YhdCpPq8P4hA\n"
                "+R14+dvzc1prqAcinGi4WYbVEpotRS4chYC4E6KSaNnEvHPujNiqdOtCouol8v9H\n"
                "BJLtMzmqvFpQmWHzDANh/6+twY6/IHHka80JliECgYAElUxgnlHlHrH9NqsjreyK\n"
                "PzcqAmrL4QdkF3gb9GPWI0jzULYpDzlIYf4ur9CKKNLVirG63tbOIO4FaYHfNZBd\n"
                "kGDATU5sr14CIwpDsdAwMZX4hEXt9ebNdAE+wCOdpbmqhUOp66DYgGRouEb7SkeR\n"
                "rVsC0ms4Vhh/AFPnidIcMQKBgQC2ExhhrEovHBadoGKoS9HCTnkE7JxNUBsqIj+A\n"
                "fq/P7311hzrAp2wgsWeeSowF9ufMWBYnnP8L9aYf2SILhksOetWKLREhu6+Ckg5n\n"
                "qajqNFg/fuvPtEef5LxNKpP8Aj/JFYR+kOyjGJc55PzHWvMOOYD4sClHBuTDOyVs\n"
                "DbtnwQKBgQCklhximnO4cYZG1+wKD0LbwEcZ1ZsvZa/Lb85GkkA7bterKEp+x3fd\n"
                "aw6V1smBAPfWAkFfkVla4izWtUZxSq8OPnvPN8mkuklEdEuFrFHGwCako6L23RxM\n"
                "tWeZqgxWwSczlrS0HcDJNEjSfDIGckYBVQdMTUFHwBES44WJWWLD8Q==\n"
                "-----END RSA PRIVATE KEY-----"; //}


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

