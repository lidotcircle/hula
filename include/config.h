#pragma once


/** http configuration */
#define HTTP_MAX_WRITE_BUFFER_SIZE (1 * 1024 * 1024)   // threhold of write buffer size
#define HTTP_PARSER_STRICT 1


/** maximum write buffer size */
#define RELAY_MAX_BUFFER_SIZE (1)               // maximum write buffer size in directed relay connection
#define PROXY_MAX_BUFFER_SIZE (1)               // maximum write buffer size in proxy

/** maximum connection per multiplexer */
#define SINGLE_PROXY_MAX_CONNECTION (1 << 6)
#define SINGLE_MULTIPLEXER_MAX_CONNECTION (1 << 6)

/** timeout for a new proxy connection */
#define NEW_CONNECTION_TIMEOUT 8000

/** maximum wait time(ms) to shouldStartWrite event after an shouldStopWrite */
#define MAXIMUM_SHOULD_START_WAIT_TIMEOUT 20000


#include "logger.h"
// #define __logger logger
#define __logger Logger::logger


#if defined(_WIN32) || defined(_WIN64)
#define FUNCNAME __func__
#else
#define FUNCNAME __PRETTY_FUNCTION__
#endif // defined(_WIN32) || defined(_WIN64)


