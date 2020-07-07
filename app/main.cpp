#include <uv.h>

#include <stdlib.h>
#include <signal.h>

#include <utils.h>
#include <kclient.h>

#include <iostream>
#include <iomanip>

#include "../include/config.h"
#include "../include/libuv_utils.h"
#include "../include/kclient_libuv.h"

static bool uv_continue = true;
static bool uv_timer_set = false;
static uv_loop_t* uv_loop_global = nullptr;
static KProxyClient::Server* g_server = nullptr;

static int handle_count = 0;

static void timer_handle(uv_timer_t* timer) //{
{
    uv_timer_stop(timer);
    uv_close((uv_handle_t*)timer, UVU::delete_closed_handle<decltype(timer)>);
    uv_timer_set = false;
} //}
static void walk_callback(uv_handle_t* h, void* data) //{
{
    ++handle_count;
    std::cout << "handle: " << handle_count << std::endl;
} //}
static void walk_loop(uv_loop_t* loop) //{
{
    handle_count = 0;
    uv_walk(loop, walk_callback, nullptr);
} //}
static void interrupt_handle(int sig) //{
{
    if(uv_continue == false) {
        walk_loop(uv_loop_global);
        abort();
    }
    __logger->warn("Exiting ...");
    uv_continue = false;
    g_server->close();
} //}

int main() //{
{
    Logger::logger_init_stdout();
//    Logger::logger->disable();

    uv_loop_t loop;
    uv_loop_init(&loop);
    uv_loop_global = &loop;

    signal(SIGINT,  interrupt_handle);
    struct sigaction mm = {SIG_IGN};
    sigaction(SIGPIPE, &mm, nullptr);

    uv_tcp_t* tcp = new uv_tcp_t();
    uv_tcp_init(&loop, tcp);
    auto config = std::shared_ptr<ClientConfig>(new UVClientConfig(&loop, "../tests/client_config.json")); // FIXME object leak
    assert(config->loadFromFile(nullptr, nullptr));
    KProxyClient::UVServer server(config, tcp);
    config.reset();

    server.trylisten();
    g_server = &server;

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
    return 0;
} //}

