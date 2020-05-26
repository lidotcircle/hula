#include <uv.h>

#include <stdlib.h>
#include <signal.h>

#include <openssl/crypto.h>

#include <utils.h>
#include <kclient.h>

#include <iostream>
#include <iomanip>

#include "../include/config.h"
#include "../include/libuv_utils.h"

static bool uv_continue = true;
static uv_loop_t* uv_loop_global = nullptr;
static KProxyClient::Server* g_server = nullptr;

static void timer_handle(uv_timer_t* timer) //{
{
    uv_timer_stop(timer);
    uv_close((uv_handle_t*)timer, UVU::delete_closed_handle<decltype(timer)>);
} //}
static void interrupt_handle(int sig) //{
{
    if(uv_continue == false) {
        abort();
    }
    __logger->warn("Exiting ...");
    uv_continue = false;
    g_server->close();
} //}

int main() //{
{
    Logger::logger_init_stdout();

    uv_loop_t loop;
    uv_loop_init(&loop);
    uv_loop_global = &loop;

    signal(SIGINT,  interrupt_handle);

    KProxyClient::Server server(&loop, "../tests/client_config.json");
    server.listen();
    g_server = &server;

    while(uv_continue) {
        uv_timer_t* timer = new uv_timer_t();
        uv_timer_init(&loop, timer);
        uv_timer_start(timer, timer_handle, 1000, 0);
        uv_run(&loop, UV_RUN_ONCE);
    }

    while(uv_loop_alive(&loop)) uv_run(&loop, UV_RUN_ONCE);

    uv_loop_close(&loop);
    return 0;
} //}

