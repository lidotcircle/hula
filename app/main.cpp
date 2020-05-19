#include <uv.h>
#include <stdlib.h>

#include <openssl/crypto.h>

#include <utils.h>
#include <kclient.h>

#include <iostream>
#include <iomanip>

int main() //{
{
    Logger::logger_init_stdout();

    uv_loop_t loop;
    uv_loop_init(&loop);

    KProxyClient::Server server(&loop, "../tests/client_config.json");
    server.listen();

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
    return 0;
} //}

