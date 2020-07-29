#include "../include/kclient_manager_libuv.h"

#include "../include/http_file_server.h"
#include "../include/libuv_utils.h"
#include "../include/ObjectFactory.h"
#include "../include/http_file_server_config.h"

#include "cert.h"

using namespace KProxyClient;
static bool uv_continue = true;
static bool uv_timer_set = false;
static int handle_count = 0;
static uv_loop_t* g_loop = nullptr;
static bool close_loop = true;

static ServerManager* manager = nullptr;

void close_global_loop_atexit() {if(!close_loop) uv_loop_close(g_loop); close_loop = true;}
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
    manager->close();
    uv_continue = false;
} //}
static void timer_handle(uv_timer_t* timer) //{
{
    uv_timer_stop(timer);
    uv_close((uv_handle_t*)timer, UVU::delete_closed_handle<decltype(timer)>);
    uv_timer_set = false;
} //}

int main() {
    uv_loop_t loop;
    uv_loop_init(&loop);
    g_loop = &loop;
    close_loop = false;
    atexit(close_global_loop_atexit);

    signal(SIGINT,  interrupt_handle);
    struct sigaction mm = {SIG_IGN};
    sigaction(SIGPIPE, &mm, nullptr);

    auto __manager = new ServerManagerUV("../tests/httpfileserver_config.json", &loop);
    __manager->start();

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
}

