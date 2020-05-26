#include "../include/libuv_utils.h"

#include <iostream>


namespace UVU {

struct __nextTick__ {void(*m_func)(void*); void* m_data;};
static void nextTick__callback(uv_timer_t* timer) //{
{
    __nextTick__* a = static_cast<decltype(a)>(uv_handle_get_data((uv_handle_t*)timer));
    uv_timer_stop(timer);
    a->m_func(a->m_data);
    uv_close((uv_handle_t*)timer, delete_closed_handle<decltype(timer)>);
} //}
void nextTick(uv_loop_t* loop, void(*func)(void*), void* data) //{
{
    uv_timer_t* timer = new uv_timer_t();
    uv_timer_init(loop, timer);
    uv_handle_set_data((uv_handle_t*)timer, new __nextTick__ {func, data});
    uv_timer_start(timer, nextTick__callback, 0, 0);
} //}

}
