#include <uv.h>
#include <stdlib.h>

#include <openssl/crypto.h>

#include <utils.h>
#include <kserver.h>

#include <iostream>
#include <iomanip>

void query_dns(uv_loop_t* p_loop, const char* addr) //{
{
    struct addrinfo hints;
    hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;

    uv_getaddrinfo_t* p_req = (uv_getaddrinfo_t*)malloc(sizeof(uv_getaddrinfo_t));

    uv_getaddrinfo(p_loop, p_req, [](uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
            struct addrinfo *a;
            struct sockaddr_in* m;
            if(status == UV_ECANCELED) {
                std::cout << "dns query be cancelled." << std::endl;
                return;
            }
            for(a = res; a != nullptr; a = a->ai_next) {
                if(sizeof(struct sockaddr_in) != a->ai_addrlen) {
                    std::cout << "problem" << std::endl;
                    continue;
                }
                m = (struct sockaddr_in*)a->ai_addr;
                /*
                char* addr = inet_ntoa(m->sin_addr);
                std::cout << "address: " << addr << std::endl;
                */
            }
    }, addr, "80", &hints);
} //}

int start_server(uv_loop_t *p_loop, const char* bind_addr, const char* bind_port) //{
{
    uv_tcp_t* p_tcp_socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    uv_tcp_init(p_loop, p_tcp_socket);

    // int port = std::stoi(bind_port); MSVC++ fail
    int port = 3333;

    struct sockaddr_in addr;
    uv_ip4_addr(bind_addr, port, &addr);

    uv_tcp_bind(p_tcp_socket, (struct sockaddr*)&addr, 0);

    return uv_listen((uv_stream_t*)p_tcp_socket, 100, nullptr);
} //}

void connectEcho(EventEmitter* target, const std::string& ename, void* args) //{
{
    uv_tcp_t* client;
    std::tie(client) = *(KProxyServer::Server::connectionType*)args;
    sockaddr_in addr;
    int len;
    uv_tcp_getpeername(client, (sockaddr*)&addr, &len);
    Logger::logger->info("new connection from %s:%d", ip4_to_str(addr.sin_addr.s_addr), addr.sin_port);
} //}

static bool uv_continue = true;
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

    KProxyServer::Server server(&loop, "../tests/server_config.json");
    server.listen();

    while(uv_continue)
        uv_run(&loop, UV_RUN_NOWAIT);

    __logger->warn("Exiting ...");
    server.close();

    while(server.HasConnection())
        uv_run(&loop, UV_RUN_NOWAIT);

    while(uv_loop_alive(&loop))
        uv_run(&loop, UV_RUN_ONCE);

    uv_loop_close(&loop);
    return 0;
} //}

