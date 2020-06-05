#pragma once 
#include "robuf.h"
#include "libuv_utils.h"

#include <uv.h>

#include <set>

template<typename O>
class TCPAbstractConnection //{
{
    public:
        /** #status<0 means error */
        using WriteCallback = void (*)(O* obj, ROBuf buf, int status);
        using ReadCallback = void(*)(O* obj, ROBuf buf, int status);

    protected:
        virtual void _write(ROBuf buf, WriteCallback cb) = 0;

        virtual void read_callback(ROBuf buf, int status) = 0;

    public:
        inline virtual ~TCPAbstractConnection() {};
}; //}


template<typename O>
class UVTCPAbstractConnection: public TCPAbstractConnection<O> //{
{
    public:
        using WriteCallback = typename TCPAbstractConnection<O>::WriteCallback;

    protected:
        struct __write_state {
            O* _this; 
            ROBuf* _holder; 
            uv_buf_t* _uv_buf; 
            bool should_run = true;
            WriteCallback _cb;
            __write_state(O* _this, ROBuf* _holder, uv_buf_t* _uv_buf, WriteCallback cb):
                _this(_this), _holder(_holder), _uv_buf(_uv_buf), _cb(cb) {}
        };
        std::set<__write_state*> m_write_callback_list;
        void insert_callback(__write_state*);
        void remove_callback(__write_state*);

        uv_tcp_t* m_connection;

        static void uv_read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
        static void uv_write_callback(uv_write_t* req, int status);
        void _write(ROBuf buf, WriteCallback cb);

    public:
        UVTCPAbstractConnection(uv_tcp_t* connection);

        void getConnection(uv_tcp_t* connection);
        uv_tcp_t* transfer();

        ~UVTCPAbstractConnection();
}; //}


inline static void uv_malloc_cb(uv_handle_t*, size_t suggested_size, uv_buf_t* buf) //{
{
    buf->base = (char*)malloc(suggested_size);
    buf->len  = suggested_size;
} //}
//             << class UVTCPAbstractConnection >>           //{
template<typename O>
UVTCPAbstractConnection<O>::UVTCPAbstractConnection(uv_tcp_t* tcp_connection): m_connection(nullptr) //{
{
    this->getConnection(tcp_connection);
} //}
template<typename O>
void UVTCPAbstractConnection<O>::getConnection(uv_tcp_t* connection) //{
{
    assert(this->m_connection == nullptr);
    this->m_connection = connection;
    uv_handle_set_data((uv_handle_t*)this->m_connection, this);
    uv_read_start((uv_stream_t*)this->m_connection, uv_malloc_cb, UVTCPAbstractConnection<O>::uv_read_callback);
} //}
/** static */
template<typename O>
void UVTCPAbstractConnection<O>::uv_read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    UVTCPAbstractConnection<O>* _this = static_cast<decltype(_this)>(uv_handle_get_data((uv_handle_t*) stream));
    bool is_client = (dynamic_cast<UVTCPAbstractConnection<O>*>(_this) != nullptr);
    ROBuf rbuf(buf->base, nread, 0, free);
    if(nread <= 0) {
        _this->read_callback(rbuf, -1);
        return;
    }
    _this->read_callback(rbuf, 0);
    return;
} //}
template<typename O>
void UVTCPAbstractConnection<O>::_write(ROBuf buf, WriteCallback cb) //{
{
    uv_write_t* req = new uv_write_t();
    uv_buf_t* uv_buf = new uv_buf_t();
    uv_buf->base = buf.__base();
    uv_buf->len = buf.size();
    ROBuf* memory_holder = new ROBuf(buf);
    auto ptr = new __write_state(dynamic_cast<O*>(this), memory_holder, uv_buf, cb);
    this->insert_callback(ptr);
    uv_req_set_data((uv_req_t*)req, ptr);
    uv_write(req, (uv_stream_t*)this->m_connection, uv_buf, 1, UVTCPAbstractConnection<O>::uv_write_callback);
} //}
/** static */
template<typename O>
void UVTCPAbstractConnection<O>::uv_write_callback(uv_write_t* req, int status) //{
{
    __write_state* state = static_cast<decltype(state)>(uv_req_get_data((uv_req_t*)req));
    delete req;
    bool should_run = state->should_run;
    WriteCallback cb = state->_cb;
    delete state->_uv_buf;
    ROBuf buf(*state->_holder);
    delete state->_holder;
    O* _this = state->_this;
    delete state;
    if(!should_run) {
        cb(nullptr, buf, status);
        return;
    }
    _this->remove_callback(state);
    cb(_this, buf, status);
} //}
template<typename O>
uv_tcp_t* UVTCPAbstractConnection<O>::transfer() //{
{
    assert(this->m_connection != nullptr);
    uv_read_stop((uv_stream_t*)this->m_connection);
    auto ret = this->m_connection;
    this->m_connection = nullptr;
    return ret;
} //}
template<typename O>
void UVTCPAbstractConnection<O>::insert_callback(__write_state* ptr) //{
{
    assert(this->m_write_callback_list.find(ptr) == this->m_write_callback_list.end());
    this->m_write_callback_list.insert(ptr);
} //}
template<typename O>
void UVTCPAbstractConnection<O>::remove_callback(__write_state* ptr) //{
{
    assert(this->m_write_callback_list.find(ptr) != this->m_write_callback_list.end());
    this->m_write_callback_list.erase(this->m_write_callback_list.find(ptr));
} //}
template<typename O>
UVTCPAbstractConnection<O>::~UVTCPAbstractConnection() //{
{
    if(this->m_connection != nullptr) {
        uv_read_stop((uv_stream_t*)this->m_connection);
        uv_close((uv_handle_t*)this->m_connection, UVU::delete_closed_handle<decltype(this->m_connection)>);
    }
    for(auto& x: this->m_write_callback_list) x->should_run = false;
} //}
//}

