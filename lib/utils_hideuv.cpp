#include "./utils_hideuv.h"

#include <uv.h>

int __ip4_addr(const char* ip, int port, struct sockaddr_in* addr) {return uv_ip4_addr(ip, port, addr);}

bool __k_inet_ntop(int af, const void* src, char* dst, size_t size) {return uv_inet_ntop(af, src, dst, size) == 0;}
bool __k_inet_pton(int af, const char* src, void* dst)              {return uv_inet_pton(af, src, dst) == 0;}

std::pair<std::string, uint16_t> __k_sockaddr_to_str(struct sockaddr* addr) //{
{
    static char addr_save[100];
    if(addr->sa_family == AF_INET) {
        struct sockaddr_in* in = (decltype(in))addr;
        if(!__k_inet_ntop(AF_INET, &in->sin_addr, addr_save, sizeof(addr_save))) return std::make_pair("", 0);
        auto port = ntohs(in->sin_port);
        return std::make_pair(std::string(addr_save), port);
    } else if(addr->sa_family == AF_INET6) {
        struct sockaddr_in6* in6 = (decltype(in6))addr;
        if(!__k_inet_ntop(AF_INET6, &in6->sin6_addr, addr_save, sizeof(addr_save))) return std::make_pair("", 0);
        auto port = ntohs(in6->sin6_port);
        return std::make_pair(std::string(addr_save), port);
    } else {
        return std::make_pair("", 0);
    }
} //}

