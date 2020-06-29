#include "../include/stream_libuv.hpp"

#include "stream_libuv_cb_data.h"

#include <assert.h>

#define DEFAULT_BACKLOG 100

/** malloc callback for uv_read */
static void malloc_cb(uv_handle_t*, size_t suggested_size, uv_buf_t* buf) //{
{
    buf->base = (char*)malloc(suggested_size);
    buf->len  = suggested_size;
} //}
template<typename T>
static void delete_closed_handle(uv_handle_t* h) {delete static_cast<T>(static_cast<void*>(h));}


void EBStreamUV::_write(ROBuf buf, WriteCallback cb, void* data) //{
{
    uv_buf_t* uv_buf = new uv_buf_t();
    uv_buf->base = buf.__base();
    uv_buf->len  = buf.size();

    uv_write_t* req = new uv_write_t();
    auto ptr = new EBStreamUV$_write$uv_write(this, buf, uv_buf, cb, data);
    uv_req_set_data((uv_req_t*)req, ptr);

    uv_write(req, (uv_stream_t*)this->mp_tcp, uv_buf, 1, EBStreamUV::uv_write_callback);
} //}
/** [static] */
void EBStreamUV::uv_write_callback(uv_write_t* req, int status) //{
{
    EBStreamUV$_write$uv_write* msg = 
        dynamic_cast<decltype(msg)>(static_cast<UVARG*>(uv_req_get_data((uv_req_t*)req)));
    assert(msg);
    delete req;

    auto _this  = msg->_this;
    auto cb     = msg->_cb;
    auto data   = msg->_data;
    auto buf    = msg->_buf;
    auto uv_buf = msg->_uv_buf;

    delete uv_buf;
    delete msg;

    cb(_this, buf, status, data);
} //}

bool EBStreamUV::bind(struct sockaddr* addr) //{
{
    assert(this->mp_tcp != nullptr);
    return uv_tcp_bind(this->mp_tcp, addr, 0) < 0 ? false : true;
} //}
bool EBStreamUV::listen() //{
{
    assert(this->mp_tcp != nullptr);
    return uv_listen((uv_stream_t*)this->mp_tcp, DEFAULT_BACKLOG, uv_connection_callback) < 0 ? false : true;
} //}
/** [static] */
void EBStreamUV::uv_connection_callback(uv_stream_t* stream, int status) //{
{
    EBStreamUV* _this = static_cast<decltype(_this)>(uv_handle_get_data((uv_handle_t*)stream));
    if(status < 0) {
        _this->on_connection(nullptr);
        return;
    }
    uv_loop_t* loop = uv_handle_get_loop((uv_handle_t*)stream);
    uv_tcp_t* newcon = new uv_tcp_t();
    uv_tcp_init(loop, newcon);
    if(uv_accept((uv_stream_t*)stream, (uv_stream_t*)newcon) < 0) {
        uv_close((uv_handle_t*)newcon, delete_closed_handle<decltype(newcon)>);
        _this->on_connection(nullptr);
    } else {
        _this->on_connection(newcon);
    }
} //}

bool EBStreamUV::connect(struct sockaddr* addr, ConnectCallback cb, void* data) //{
{
    auto ptr = new EBStreamUV$connect$uv_connect(this, cb, data);
    uv_connect_t* req = new uv_connect_t();
    uv_req_set_data((uv_req_t*)req, ptr);
    return uv_tcp_connect(req, this->mp_tcp, addr, uv_connect_callback) < 0 ?
        false :
        true;
} //}
/** [static] */
void EBStreamUV::uv_connect_callback(uv_connect_t* req, int status) //{
{
    EBStreamUV$connect$uv_connect* msg =
        dynamic_cast<decltype(msg)>(static_cast<UVARG*>(uv_req_get_data((uv_req_t*)req)));
    assert(msg);
    delete req;

    auto _this = msg->_this;
    auto _cb   = msg->_cb;
    auto _data = msg->_data;
    delete msg;

    _cb(_this, status, _data);
} //}

/** wrapper of uv_read_start() and uv_read_stop() */
void EBStreamUV::stop_read() //{
{
    assert(this->m_stream_read == true);
    uv_read_stop((uv_stream_t*)this->mp_tcp);
    this->m_stream_read = false;
} //}
void EBStreamUV::start_read() //{
{
    assert(this->m_stream_read == false);
    uv_read_start((uv_stream_t*)this->mp_tcp, malloc_cb, EBStreamUV::uv_stream_read_callback);
    this->m_stream_read = true;
} //}
/** [static] */
void EBStreamUV::uv_stream_read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    EBStreamUV* _this = static_cast<decltype(_this)>(uv_handle_get_data((uv_handle_t*)stream));

    if(nread <= 0) {
        _this->read_callback(ROBuf(), -1);
        free(buf->base);
        return;
    }

    ROBuf rbuf(buf->base, nread, 0);
    _this->read_callback(rbuf, 0);
} //}

/** read state of the stream */
bool EBStreamUV::in_read() //{
{
    return this->m_stream_read;
} //}

void EBStreamUV::getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) //{
{
    auto ptr = new EBStreamUV$getaddrinfo$uv_getaddrinfo(this, cb, data);
    uv_getaddrinfo_t* req = new uv_getaddrinfo_t();
    uv_req_set_data((uv_req_t*)req, ptr);

    struct addrinfo hints;
    hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;

    uv_getaddrinfo(uv_handle_get_loop((uv_handle_t*)this->mp_tcp), req, EBStreamUV::uv_getaddrinfo_callback,
            hostname, "80", &hints);
} //}
/** [static] */
void EBStreamUV::uv_getaddrinfo_callback(uv_getaddrinfo_t* req, int status, struct addrinfo* res) //{
{
    struct addrinfo *a;
    struct sockaddr_in* m;

    EBStreamUV$getaddrinfo$uv_getaddrinfo* msg =
        dynamic_cast<decltype(msg)>(static_cast<UVARG*>(uv_req_get_data((uv_req_t*)req)));
    assert(msg);
    delete req;

    auto _this = msg->_this;
    auto _cb   = msg->_cb;
    auto _data = msg->_data;
    delete msg;

    _cb(_this, res, status, _data);
    return;
} //}
void EBStreamUV::freeaddrinfo(struct addrinfo* addr) //{
{
    uv_freeaddrinfo(addr);
} //}

void* EBStreamUV::newUnderlyStream() //{
{
    assert(this->mp_tcp != nullptr);
    uv_loop_t* loop = uv_handle_get_loop((uv_handle_t*)this->mp_tcp);
    uv_tcp_t* ret = new uv_tcp_t();
    uv_tcp_init(loop, ret);
    return ret;
} //}
void  EBStreamUV::releaseUnderlyStream(void* ptr) //{
{
    uv_tcp_t* tcp = static_cast<decltype(tcp)>(ptr);
    uv_close((uv_handle_t*)tcp, delete_closed_handle<decltype(tcp)>);
} //}
bool  accept(void* listen, void* stream) //{
{
    return uv_accept(static_cast<uv_stream_t*>(listen), static_cast<uv_stream_t*>(stream)) < 0 ?
        false :
        true;
} //}

EBStreamUV::EBStreamUV(uv_tcp_t* tcp) //{
{
    this->mp_tcp = tcp;
    if(this->mp_tcp != nullptr)
        uv_handle_set_data((uv_handle_t*)this->mp_tcp, this);
    this->m_stream_read = false;
} //}
EBStreamUV::~EBStreamUV() //{
{
    if(this->mp_tcp != nullptr) {
        if(this->in_read())
            this->stop_read();
        uv_close((uv_handle_t*)(this->mp_tcp), delete_closed_handle<decltype(this->mp_tcp)>);
        this->mp_tcp = nullptr;
    }
} //}

void* EBStreamUV::transfer() //{
{
    if(this->in_read()) this->stop_read();
    auto ret = this->mp_tcp;
    this->mp_tcp = nullptr;
    return ret;
} //}
void  EBStreamUV::regain(void* ptr) //{
{
    assert(this->in_read() == false);
    this->mp_tcp = static_cast<decltype(this->mp_tcp)>(ptr);
    uv_handle_set_data((uv_handle_t*)this->mp_tcp, this);
} //}

