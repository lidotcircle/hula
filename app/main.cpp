#include <uv.h>

#include <stdlib.h>
#include <signal.h>

#include <openssl/crypto.h>

#include <utils.h>
#include <kclient.h>

#include <iostream>
#include <iomanip>

static bool uv_continue = true;

static void interrupt_handle(int sig) //{
{
    if(uv_continue == false) {
        exit(1);
    }
    uv_continue = false;
} //}

int main() //{
{
    Logger::logger_init_stdout();

    uv_loop_t loop;
    uv_loop_init(&loop);

    signal(SIGINT,  interrupt_handle);

    KProxyClient::Server server(&loop, "../tests/client_config.json");
    server.listen();

    while(uv_continue)
        uv_run(&loop, UV_RUN_ONCE);

    std::cout << "Exiting..." << std::endl;

    server.close();
    while (server.IsRunning())
        uv_run(&loop, UV_RUN_ONCE);

    uv_loop_close(&loop);
    return 0;
} //}

