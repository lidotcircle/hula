#include <uv.h>
#include <stdlib.h>

#include <openssl/crypto.h>

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
                char* addr = inet_ntoa(m->sin_addr);
                std::cout << "address: " << addr << std::endl;
            }
    }, addr, "80", &hints);
} //}

int start_server(uv_loop_t *p_loop, const char* bind_addr, const char* bind_port) //{
{
    uv_tcp_t* p_tcp_socket = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    uv_tcp_init(p_loop, p_tcp_socket);

    int port = std::stoi(bind_port);

    struct sockaddr_in addr;
    uv_ip4_addr(bind_addr, port, &addr);

    uv_tcp_bind(p_tcp_socket, (struct sockaddr*)&addr, 0);

    return uv_listen((uv_stream_t*)p_tcp_socket, 100, nullptr);
} //}

int main() //{
{
    uv_loop_t loop;
    uv_loop_init(&loop);

    query_dns(&loop, "baidu.com");

    if(start_server(&loop, "0.0.0.0", "8888") != 0) {
        std::cout << "start server fail" << std::endl;
        return 1;
    }

    uv_run(&loop, UV_RUN_DEFAULT);

    return 0;
} //}

