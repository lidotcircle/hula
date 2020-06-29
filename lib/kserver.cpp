#include "../include/kserver.h"
#include "../include/logger.h"
#include "../include/utils.h"
#include "../include/kpacket.h"
#include "../include/robuf.h"
#include "../include/uv_callback_data.h"
#include "../include/libuv_utils.h"

#include <stdlib.h>
#include <assert.h>

#include <tuple>

#define CONNECTION_MAX_BUFFER_SIZE (2 * 1024 * 1024) // 2M

template<typename T>
static void delete_closed_handle(uv_handle_t* h) {delete static_cast<T>(static_cast<void*>(h));}

