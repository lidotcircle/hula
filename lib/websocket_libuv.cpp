#include "../include/websocket_libuv.h"
#include "../include/libuv_utils.h"


//             << class UVWebsocketCommon >>           //{
UVWebsocketCommon::UVWebsocketCommon(uv_tcp_t* tcp_connection, bool masked, bool save_fragment):
   WebSocketCommon(masked, save_fragment), m_connection(tcp_connection) //{
{
    uv_handle_set_data((uv_handle_t*)this->m_connection, this);
    this->start_read();
} //}
void UVWebsocketCommon::start_read() //{
{
    assert(this->m_connection != nullptr);
    uv_read_start((uv_stream_t*)this->m_connection, uv_malloc_cb, UVWebsocketCommon::uv_read_callback);
} //}
/** static */
void UVWebsocketCommon::uv_read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    UVWebsocketCommon* _this = static_cast<decltype(_this)>(uv_handle_get_data((uv_handle_t*) stream));
    bool is_client = (dynamic_cast<UVWebsocketClient*>(_this) != nullptr);
    ROBuf rbuf(buf->base, nread, 0, free);
    if(nread <= 0) {
        _this->read_callback(rbuf, -1);
        return;
    }
    _this->read_callback(rbuf, 0);
    return;
} //}
void UVWebsocketCommon::_write(ROBuf buf, WriteCallback cb, void* data) //{
{
    uv_write_t* req = new uv_write_t();
    uv_buf_t* uv_buf = new uv_buf_t();
    uv_buf->base = buf.__base();
    uv_buf->len = buf.size();
    ROBuf* memory_holder = new ROBuf(buf);
    auto ptr = new __write_state(this, memory_holder, uv_buf, cb, data);
    this->insert_callback(ptr);
    uv_req_set_data((uv_req_t*)req, ptr);
    uv_write(req, (uv_stream_t*)this->m_connection, uv_buf, 1, UVWebsocketCommon::uv_write_callback);
} //}
/** static */
void UVWebsocketCommon::uv_write_callback(uv_write_t* req, int status) //{
{
    __write_state* state = static_cast<decltype(state)>(uv_req_get_data((uv_req_t*)req));
    delete req;
    bool should_run = state->should_run;
    WriteCallback cb = state->_cb;
    delete state->_uv_buf;
    ROBuf buf(*state->_holder);
    delete state->_holder;
    UVWebsocketCommon* _this = state->_this;
    void* data = state->_data;
    delete state;
    if(!should_run) {
        cb(nullptr, buf, status, data);
        return;
    }
    _this->remove_callback(state);
    cb(_this, buf, status, data);
} //}
void UVWebsocketCommon::stop_read() //{
{
    uv_read_stop((uv_stream_t*)this->m_connection);
} //}
uv_tcp_t* UVWebsocketCommon::transfer() //{
{
    assert(this->m_connection != nullptr);
    auto ret = this->m_connection;
    this->m_connection = nullptr;
    return ret;
} //}
void UVWebsocketCommon::insert_callback(__write_state* ptr) //{
{
    assert(this->m_write_callback_list.find(ptr) == this->m_write_callback_list.end());
    this->m_write_callback_list.insert(ptr);
} //}
void UVWebsocketCommon::remove_callback(__write_state* ptr) //{
{
    assert(this->m_write_callback_list.find(ptr) != this->m_write_callback_list.end());
    this->m_write_callback_list.erase(this->m_write_callback_list.find(ptr));
} //}
UVWebsocketCommon::~UVWebsocketCommon() //{
{
    if(this->m_connection != nullptr) {
        uv_read_stop((uv_stream_t*)this->m_connection);
        uv_close((uv_handle_t*)this->m_connection, UVU::delete_closed_handle<decltype(this->m_connection)>);
    }
    for(auto& x: this->m_write_callback_list) x->should_run = false;
} //}
//}

UVWebsocketClient::UVWebsocketClient(uv_tcp_t* connection, bool save_fragment):
    UVWebsocketCommon(connection, true, save_fragment) {}

UVWebsocketServer::UVWebsocketServer(uv_tcp_t* connection, bool save_fragment):
    UVWebsocketCommon(connection, false, save_fragment) {}

