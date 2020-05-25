#pragma once

#include <uv.h>

namespace UVU {

void nextTick(uv_loop_t*, void (*)(void*), void*);

}

