#include "../include/config_file.h"
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

void load_cb(int error, void* data) //{
{
    if(error > 0) Logger::logger->debug("%s", strerror(error));
    assert(error <= 0);
    ClientConfig* config = (ClientConfig*)data;

    std::cout << "-- pass read config test" << std::endl;

    config->Users()["test"] = "test_password";
    config->new_file("./good.json");

    config->writeToFile(write_cb, config);
} //}

void test_client_config(uv_loop_t* loop) //{
{
    ClientConfig* config = new ClientConfig(loop, "../tests/client_config.json");
    config->loadFromFile(load_cb, config);
} //}


int main() //{
{
    Logger::logger_init_stdout();
    uv_loop_t loop;
    uv_loop_init(&loop);

    test_client_config(&loop);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
    return 0;
} //}

