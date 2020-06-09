#pragma once

#include "websocket.hpp"

#include <set>

#include <uv.h>

class UVWebsocketCommon: public WebSocketCommon //{
{
    private:
        struct __write_state {
            UVWebsocketCommon* _this; 
            ROBuf* _holder; 
            uv_buf_t* _uv_buf; 
            bool should_run = true;
            WriteCallback _cb;
            void* _data;
            __write_state(UVWebsocketCommon* _this, ROBuf* _holder, uv_buf_t* _uv_buf, WriteCallback cb, void* data):
                _this(_this), _holder(_holder), _uv_buf(_uv_buf), _cb(cb), _data(data) {}
        };
        std::set<__write_state*> m_write_callback_list;
        void insert_callback(__write_state*);
        void remove_callback(__write_state*);

        uv_tcp_t* m_connection;

        void start_read();
        void stop_read();
        static void uv_read_callback (uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
        static void uv_write_callback(uv_write_t* req, int status);

    protected:
        void _write(ROBuf buf, WriteCallback cb, void* data); 

    public:
        UVWebsocketCommon(uv_tcp_t* tcp_connection, bool masked, bool save_fragment);
        uv_tcp_t* transfer();
        ~UVWebsocketCommon();
}; //}

class UVWebsocketClient: public UVWebsocketCommon //{
{
    public:
        UVWebsocketClient(uv_tcp_t* connection, bool save_fragment = false);
}; //}
class UVWebsocketServer: public UVWebsocketCommon //{
{
    public:
        UVWebsocketServer(uv_tcp_t* connection, bool save_fragment = false);
}; //}


