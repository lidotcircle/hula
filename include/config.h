// CONFIG
#pragma once

#define RELAY_MAX_BUFFER_SIZE (1 * 1024 * 1024)
#define PROXY_MAX_BUFFER_SIZE (1 * 1024 * 1024)

#define PROXY_MAX_BUFFER_SIZE_XXX (10 * 1024 * 1024)

#define MAX_LISTEN 500

// #define __logger logger
 #define __logger Logger::logger

#if defined(_WIN32) || defined(_WIN64)
#define FUNCNAME __PRETTY_FUNCTION__
#else
#define FUNCNAME __func__
#endif // defined(_WIN32) || defined(_WIN64)

