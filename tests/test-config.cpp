#include "../include/kclient_config.h"
#include "../include/kserver_config.h"
#include "../include/logger.h"

#include <assert.h>
#include <string.h>

void write_cb(int error, void* data) //{
{
    if(error > 0) Logger::logger->debug("%s", strerror(error));
    assert(error <= 0);
    ClientConfig* config = (ClientConfig*)data;

    std::cout << "-- pass write back test" << std::endl;

    delete config;
} //}

void load_cb_server(int error, void* data) //{
{
    if(error > 0) Logger::logger->debug("%s", strerror(error));
    assert(error <= 0);
    ServerConfig* config = (ServerConfig*)data;

    assert(config->validateUser("admin", "password"));
    assert(!config->validateUser("xadmin", "password"));

    delete config;
} //}

void load_cb(int error, void* data) //{
{
    if(error > 0) Logger::logger->debug("%s", strerror(error));
    assert(error <= 0);
    ClientConfig* config = (ClientConfig*)data;

    std::cout << "-- pass read config test" << std::endl;

    config->Users()["test"] = "test_password";

    config->writeToFile(write_cb, config);
} //}

void test_client_config(uv_loop_t* loop) //{
{
    ClientConfig* config = new UVClientConfig(loop, "../tests/client_config.json");
    config->loadFromFile(load_cb, config);
} //}

void test_server_config(uv_loop_t* loop) //{
{
    ServerConfig* config = new UVServerConfig(loop, "../tests/server_config.json");
    config->loadFromFile(load_cb_server, config);
} //}

void test_server_config2(uv_loop_t* loop) //{
{
    ServerConfig* config = new UVServerConfig(loop, "../tests/server_config.json");
    config->loadFromFile(nullptr, nullptr);

    assert(config->validateUser("admin", "password"));
    assert(!config->validateUser("xadmin", "password"));
} //}

int main() //{
{
    Logger::logger_init_stdout();
    uv_loop_t loop;
    uv_loop_init(&loop);

    test_client_config(&loop);
    test_server_config(&loop);
    test_server_config2(&loop);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
    return 0;
} //}

