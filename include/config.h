// CONFIG
#pragma once

#define MAX_WRITE_BUFFER_SIZE (1 * 1024 * 1024)

#define RELAY_MAX_BUFFER_SIZE (1 * 1024 * 1024)
#define PROXY_MAX_BUFFER_SIZE (1 * 1024 * 1024)

#define PROXY_MAX_BUFFER_SIZE_XXX (10 * 1024 * 1024)

#define MAX_LISTEN 500

#include "logger.h"
// #define __logger logger
 #define __logger Logger::logger

#define HTTP_PARSER_STRICT 1

#if defined(_WIN32) || defined(_WIN64)
#define FUNCNAME __func__
#else
#define FUNCNAME __PRETTY_FUNCTION__
#endif // defined(_WIN32) || defined(_WIN64)

