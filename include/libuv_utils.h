#pragma once

#include <uv.h>

namespace UVU {

void nextTick(uv_loop_t*, void (*)(void*), void*);

template<typename T>
void delete_closed_handle(uv_handle_t* h) {delete static_cast<T>(static_cast<void*>(h));}

}

