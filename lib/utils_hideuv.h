#pragma once

#include <stdlib.h>

#include <string>


int __ip4_addr(const char* ip, int port, struct sockaddr_in* addr);

bool __k_inet_ntop(int af, const void* src, char* dst, size_t size);
bool __k_inet_pton(int af, const char* src, void* dst);

std::pair<std::string, uint16_t> __k_sockaddr_to_str(struct sockaddr* addr);

