#pragma once

#include <openssl/ssl.h>
#include <openssl/crypto.h>

#include <assert.h>

#define xassert(expr) assert(expr)

#include "logger.h"

extern Logger::Logger* logger;


X509* mem2cert(void* m, size_t len);
RSA*  mem2rsa (void* m, size_t len);;


uint64_t k_htonll(uint64_t);
uint64_t k_ntohll(uint64_t);
uint32_t k_htonl(uint32_t);
uint32_t k_ntohl(uint32_t);
uint16_t k_htons(uint16_t);
uint16_t k_ntohs(uint16_t);

char* ip4_to_str(uint32_t ip4);
bool str_to_ip4(const char*, uint32_t* out);

