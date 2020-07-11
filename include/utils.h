#pragma once

#include <openssl/ssl.h>
#include <openssl/crypto.h>

#include <assert.h>

#define xassert(expr) assert(expr)

#include "logger.h"

extern Logger::Logger* logger;


X509* mem2cert(void* m, size_t len);
RSA*  mem2rsa (void* m, size_t len);;


uint32_t k_htonl(uint32_t);
uint32_t k_ntohl(uint32_t);
uint16_t k_htons(uint16_t);
uint16_t k_ntohs(uint16_t);

template<typename T>
T changeByteOrder(T integer) //{
{
    static_assert(std::is_integral<T>(), "need integer type");
    uint8_t *a, *b;
    for(int i=0; i<(sizeof(T) / 2); i++) {
        a = static_cast<uint8_t*>(static_cast<void*>(static_cast<char*>(static_cast<void*>(&integer)) + i));
        b = static_cast<uint8_t*>(static_cast<void*>(static_cast<char*>(static_cast<void*>(&integer)) + sizeof(T) - i - 1));
        uint8_t t = *a;
        *a = *b;
        *b = t;
    }
    return integer;
} //}

constexpr auto k_htonll = changeByteOrder<uint64_t>;
constexpr auto k_ntohll = changeByteOrder<uint64_t>;

char* ip4_to_str(uint32_t ip4);
bool  str_to_ip4(const char*, uint32_t* out);
int   ip4_addr(const char* ip, int port, struct sockaddr_in* addr);

bool k_inet_ntop(int af, const void* src, char* dst, size_t size);
bool k_inet_pton(int af, const char* src, void* dst);
std::pair<std::string, uint16_t> k_sockaddr_to_str(struct sockaddr*);

