#include "../include/tcpabstraction.h"

#include <iostream>
#include <iomanip>

//             << class UVTCPAbstractConnection >>           //{
UVTCPAbstractConnection::UVTCPAbstractConnection(uv_tcp_t* tcp_connection): m_connection(nullptr) //{
{
    this->getConnection(tcp_connection);
    this->start_read();
} //}
void UVTCPAbstractConnection::getConnection(uv_tcp_t* connection) //{
{
    assert(this->m_connection == nullptr);
    this->m_connection = connection;
    uv_handle_set_data((uv_handle_t*)this->m_connection, this);
    this->m_start_read = false;
} //}
void UVTCPAbstractConnection::start_read() //{
{
    assert(this->m_start_read == false);
    uv_read_start((uv_stream_t*)this->m_connection, uv_malloc_cb, UVTCPAbstractConnection::uv_read_callback);
    this->m_start_read = true;
} //}
/** static */
void UVTCPAbstractConnection::uv_read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    UVTCPAbstractConnection* _this = static_cast<decltype(_this)>(uv_handle_get_data((uv_handle_t*) stream));
    bool is_client = (dynamic_cast<UVTCPAbstractConnection*>(_this) != nullptr);
    ROBuf rbuf(buf->base, nread, 0, free);
    if(nread <= 0) {
        _this->read_callback(rbuf, -1);
        return;
    }
    _this->read_callback(rbuf, 0);
    return;
} //}
void UVTCPAbstractConnection::_write(ROBuf buf, WriteCallback cb, void* data) //{
{
    uv_write_t* req = new uv_write_t();
    uv_buf_t* uv_buf = new uv_buf_t();
    uv_buf->base = buf.__base();
    uv_buf->len = buf.size();
    ROBuf* memory_holder = new ROBuf(buf);
    auto ptr = new __write_state(this, memory_holder, uv_buf, cb, data);
    this->insert_callback(ptr);
    uv_req_set_data((uv_req_t*)req, ptr);
    uv_write(req, (uv_stream_t*)this->m_connection, uv_buf, 1, UVTCPAbstractConnection::uv_write_callback);
} //}
/** static */
void UVTCPAbstractConnection::uv_write_callback(uv_write_t* req, int status) //{
{
    __write_state* state = static_cast<decltype(state)>(uv_req_get_data((uv_req_t*)req));
    delete req;
    bool should_run = state->should_run;
    WriteCallback cb = state->_cb;
    delete state->_uv_buf;
    ROBuf buf(*state->_holder);
    delete state->_holder;
    UVTCPAbstractConnection* _this = state->_this;
    void* data = state->_data;
    delete state;
    if(!should_run) {
        cb(nullptr, buf, status, data);
        return;
    }
    _this->remove_callback(state);
    cb(_this, buf, status, data);
} //}
void UVTCPAbstractConnection::stop_read() //{
{
    assert(this->m_start_read);
    assert(this->m_connection != nullptr);
    uv_read_stop((uv_stream_t*)this->m_connection);
    this->m_start_read = false;
} //}
uv_tcp_t* UVTCPAbstractConnection::transfer() //{
{
    auto ret = this->m_connection;
    this->m_connection = nullptr;
    return ret;
} //}
void UVTCPAbstractConnection::insert_callback(__write_state* ptr) //{
{
    assert(this->m_write_callback_list.find(ptr) == this->m_write_callback_list.end());
    this->m_write_callback_list.insert(ptr);
} //}
void UVTCPAbstractConnection::remove_callback(__write_state* ptr) //{
{
    assert(this->m_write_callback_list.find(ptr) != this->m_write_callback_list.end());
    this->m_write_callback_list.erase(this->m_write_callback_list.find(ptr));
} //}
UVTCPAbstractConnection::~UVTCPAbstractConnection() //{
{
    if(this->m_connection != nullptr) {
        uv_read_stop((uv_stream_t*)this->m_connection);
        uv_close((uv_handle_t*)this->m_connection, UVU::delete_closed_handle<decltype(this->m_connection)>);
    }
    for(auto& x: this->m_write_callback_list) x->should_run = false;
} //}
//}


//             << class MemoryTCPAbstractConnection >>           //{
MemoryTCPAbstractConnection::MemoryTCPAbstractConnection(): m_buffer() //{
{
    this->m_start_read = false;
    this->start_read();
} //}
void MemoryTCPAbstractConnection::_write(ROBuf buf, WriteCallback cb, void* data) //{
{
    for(int i=0;i<buf.size();i++) {
        this->m_buffer << buf.base()[i];
        std::cout << buf.base()[i];
    }
    cb(this, buf, 0, data);
} //}
void MemoryTCPAbstractConnection::start_read() //{
{
    assert(this->m_start_read == false);
    this->m_start_read = true;
} //}
void MemoryTCPAbstractConnection::stop_read() //{
{
    assert(this->m_start_read);
    this->m_start_read = false;
} //}
MemoryTCPAbstractConnection::~MemoryTCPAbstractConnection() //{
{
} //}
//}

