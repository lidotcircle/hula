#include <uv.h>
#include <stdlib.h>

#include <openssl/crypto.h>

#include <utils.h>
#include <kserver.h>

#include <iostream>
#include <iomanip>
#include <memory>

#include "../include/libuv_utils.h"
#include "../include/kserver_libuv.h"

static bool uv_continue = true;
static bool uv_timer_set = false;
static void timer_handle(uv_timer_t* timer) //{
{
    uv_timer_stop(timer);
    uv_close((uv_handle_t*)timer, UVU::delete_closed_handle<decltype(timer)>);
    uv_timer_set = false;
} //}
static void interrupt_handle(int sig) //{
{
    if(uv_continue == false) {
        abort();
    }
    uv_continue = false;
} //}

int main() //{
{
    Logger::logger_init_stdout();
    uv_loop_t loop;
    uv_loop_init(&loop);

    signal(SIGINT,  interrupt_handle);
    struct sigaction mm = {SIG_IGN};
    sigaction(SIGPIPE, &mm, nullptr);

    uv_tcp_t* tcp = new uv_tcp_t();
    uv_tcp_init(&loop, tcp);
    auto config = std::shared_ptr<ServerConfig>(new ServerConfig(&loop, "../tests/server_config.json"));
    config->loadFromFile(nullptr, nullptr);
    KProxyServer::UVServer server(tcp, config);

    server.trylisten();

    while(uv_continue) {
        if(uv_timer_set == false) {
            uv_timer_t* timer = new uv_timer_t();
            uv_timer_init(&loop, timer);
            uv_timer_start(timer, timer_handle, 1000, 0);
            uv_timer_set = true;
        }
        uv_run(&loop, UV_RUN_ONCE);
    }

    __logger->warn("Exiting ...");
    server.close();
    server.transfer();
    uv_close((uv_handle_t*)tcp, nullptr);

    while(uv_loop_alive(&loop))
        uv_run(&loop, UV_RUN_ONCE);

    delete tcp;

    uv_loop_close(&loop);
    return 0;
} //}

