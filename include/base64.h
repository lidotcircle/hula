#pragma once

#include <stdlib.h>

/** (return < 0) means false */
int Base64Encode(const char* src, size_t src_len, char* dst, size_t dst_len);
int Base64Decode(const char* str, size_t src_len, char* dst, size_t dst_len);

