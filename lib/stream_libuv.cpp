#include "../include/stream_libuv.hpp"

#include "stream_libuv_cb_data.h"

#include <assert.h>
#include <string.h>

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
    assert(cb != nullptr);
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

    cb(buf, status, data);
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

    _cb(status, _data);
} //}

/** wrappers of connect */
bool EBStreamUV::connect(uint32_t ipv4, uint16_t port, ConnectCallback cb, void* data) //{
{
    sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(ipv4);
    addr.sin_port        = htons(port);
    return this->connect((sockaddr*)&addr, cb, data);
} //}
bool EBStreamUV::connect(uint8_t ipv6[16], uint16_t port, ConnectCallback cb, void* data) //{
{
    sockaddr_in6 addr;
    addr.sin6_family      = AF_INET6;
    memcpy(&addr.sin6_addr, ipv6, sizeof(*ipv6));
    addr.sin6_port        = htons(port);
    return this->connect((sockaddr*)&addr, cb, data);
} //}
struct __ppp: public CallbackPointer {
    EBStreamAbstraction::ConnectCallback _cb;
    void* _data;
    uint16_t _port;
    EBStreamUV* _this;
    bool _force_ipv6;
    __ppp(decltype(_this) _this, decltype(_cb) cb, void* data, uint16_t port): _this(_this), _cb(cb), _data(data), _port(port) {}
};
void EBStreamUV::getaddrinfo_callback(struct addrinfo* res, void(*__freeaddrinfoint)(struct addrinfo*), int status, void* data) //{
{
    struct addrinfo *a = nullptr;
    struct sockaddr* m = nullptr;

    __ppp* msg =
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto _cb   = msg->_cb;
    auto _data = msg->_data;
    auto _port = msg->_port;
    auto run   = msg->CanRun();
    auto force_ipv6 = msg->_force_ipv6;
    delete msg;

    if(!run) {
        if(res != nullptr) __freeaddrinfo(res);
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);
    
    if(status < 0 || res == nullptr) {
        if(res != nullptr) __freeaddrinfo(res);
        _cb(-1, _data);
        return;
    }

    if(!force_ipv6) {
        for(a=res;a!=nullptr;a=a->ai_next) {
            if(a->ai_family == AF_INET) {
                m = a->ai_addr;
                break;
            }
        }
    }

    if(m == nullptr) {
        for(a=res;a!=nullptr;a=a->ai_next) {
            if(a->ai_family == AF_INET6) {
                m = a->ai_addr;
                break;
            }
        }
    }

    if(m == nullptr) {
        __freeaddrinfo(res);
        _cb(-1, _data);
        return;
    }

    _this->connect(m, _cb, _data);
    __freeaddrinfo(res);
    return;
} //}
bool EBStreamUV::connect(const std::string& addr, uint16_t port, ConnectCallback cb, void* data) //{
{
    auto ptr = new __ppp(this, cb, data, port);
    ptr->_force_ipv6 = false;
    this->add_callback(ptr);

    this->getaddrinfo(addr.c_str(), getaddrinfo_callback, ptr);
    return true;
} //}
bool EBStreamUV::connectINet6(const std::string& addr, uint16_t port, ConnectCallback cb, void* data) //{
{
    auto ptr = new __ppp(this, cb, data, port);
    ptr->_force_ipv6 = true;
    this->add_callback(ptr);

    this->getaddrinfo(addr.c_str(), getaddrinfo_callback, ptr);
    return true;
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
        free(buf->base);
        if(nread < 0) _this->read_callback(ROBuf(), -1);
        else          _this->end_signal();
        return;
    }

    ROBuf rbuf(buf->base, nread, 0, free);
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
    EBStreamUV$getaddrinfo$uv_getaddrinfo* msg =
        dynamic_cast<decltype(msg)>(static_cast<UVARG*>(uv_req_get_data((uv_req_t*)req)));
    assert(msg);
    delete req;

    auto _this = msg->_this;
    auto _cb   = msg->_cb;
    auto _data = msg->_data;
    delete msg;

    _cb(res, EBStreamUV::__freeaddrinfo, status, _data);
    return;
} //}
/** [static] */
void EBStreamUV::__freeaddrinfo(struct addrinfo* addr) //{
{
    uv_freeaddrinfo(addr);
} //}

/** dns utils */
static void getaddrinfo_callback_for_getaddrinfoipv4(struct addrinfo* res, void(*__freeaddrinfo)(struct addrinfo*), int status, void* data) //{
{
    struct addrinfo *a;
    struct sockaddr_in* m;

    std::pair<EBStreamAbstraction::GetAddrInfoIPv4Callback, void*>* msg = 
        static_cast<decltype(msg)>(data);
    auto _cb   = msg->first;
    auto _data = msg->second;
    delete msg;

    if(status < 0) {
        __freeaddrinfo(res);
        _cb(0, -1, _data);
        return;
    }

    for(a = res; a != nullptr; a = a->ai_next) {
        if(sizeof(struct sockaddr_in) != a->ai_addrlen) {
            continue;
        } else break;
    }
    if(a == nullptr) {
        __freeaddrinfo(res);
        _cb(0, -1, _data);
        return;
    }
    m = (struct sockaddr_in*)a->ai_addr;
    uint32_t addr = m->sin_addr.s_addr;
    __freeaddrinfo(res);
    _cb(addr, 0, _data);
} //}
void EBStreamUV::getaddrinfoipv4 (const char* hostname, GetAddrInfoIPv4Callback cb, void* data) //{
{
    this->getaddrinfo(hostname, getaddrinfo_callback_for_getaddrinfoipv4, new std::pair<GetAddrInfoIPv4Callback, void*>(cb, data));
} //}
static void getaddrinfo_callback_for_getaddrinfoipv6(struct addrinfo* res, void(*__freeaddrinfo)(struct addrinfo*), int status, void* data) //{
{
    struct addrinfo *a;
    struct sockaddr_in6* m;

    std::pair<EBStreamAbstraction::GetAddrInfoIPv6Callback, void*>* msg = 
        static_cast<decltype(msg)>(data);
    auto _cb   = msg->first;
    auto _data = msg->second;
    delete msg;

    if(status < 0) {
        __freeaddrinfo(res);
        _cb(nullptr, -1, _data);
        return;
    }

    for(a = res; a != nullptr; a = a->ai_next) {
        if(sizeof(struct sockaddr_in6) != a->ai_addrlen) {
            continue;
        } else break;
    }
    if(a == nullptr) {
        __freeaddrinfo(res);
        _cb(0, -1, _data);
        return;
    }
    m = (struct sockaddr_in6*)a->ai_addr;
    uint8_t addr[16];
    memcpy(&addr, &m->sin6_addr, sizeof(addr));
    __freeaddrinfo(res);
    _cb(addr, 0, _data);
} //}
void EBStreamUV::getaddrinfoipv6 (const char* hostname, GetAddrInfoIPv6Callback cb, void* data) //{
{
    this->getaddrinfo(hostname, getaddrinfo_callback_for_getaddrinfoipv6, new std::pair<GetAddrInfoIPv6Callback, void*>(cb, data));
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
bool  EBStreamUV::accept(void* listen, void* stream) //{
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
    if(this->mp_tcp != nullptr)
        this->release();
} //}

struct EBStreamUV$shutdown$uv_shutdown {
    EBStreamUV::ShutdownCallback _cb;
    void* _data;
    inline EBStreamUV$shutdown$uv_shutdown(EBStreamUV::ShutdownCallback cb, void* data): 
        _cb(cb), _data(data) {}
};
static void shutdown_callback(uv_shutdown_t* req, int status) //{
{
    EBStreamUV$shutdown$uv_shutdown* msg = 
        static_cast<decltype(msg)>(uv_req_get_data((uv_req_t*)req));
    delete req;
    auto cb = msg->_cb;
    auto data = msg->_data;
    delete msg;
    cb(status, data);
} //}
void EBStreamUV::shutdown(ShutdownCallback cb, void* data) //{
{
    uv_shutdown_t* req = new uv_shutdown_t();
    auto ptr = new EBStreamUV$shutdown$uv_shutdown(cb, data);
    uv_req_set_data((uv_req_t*)req, ptr);
    uv_shutdown(req, (uv_stream_t*)this->mp_tcp, shutdown_callback);
} //}

bool  EBStreamUV::hasStreamObject() //{
{
    return this->mp_tcp != nullptr;
} //}
void EBStreamUV::release() //{
{
    assert(this->mp_tcp != nullptr);
    if(this->in_read()) this->stop_read();
    uv_close((uv_handle_t*)this->mp_tcp, delete_closed_handle<decltype(this->mp_tcp)>);
    this->mp_tcp = nullptr;
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

struct __uv_timeout_state__ {
    EBStreamAbstraction::TimeoutCallback _cb;
    void* _data; 
    __uv_timeout_state__(EBStreamAbstraction::TimeoutCallback cb, void* data): _cb(cb), _data(data) {}
};
static void __uv_timeout_callback(uv_timer_t* timer) //{
{
    __uv_timeout_state__* msg = static_cast<decltype(msg)>(uv_handle_get_data((uv_handle_t*)timer));
    uv_timer_stop(timer);
    auto cb = msg->_cb;
    auto data = msg->_data;
    delete msg;

    cb(data);

    uv_close((uv_handle_t*)timer, delete_closed_handle<decltype(timer)>);
} //}
void EBStreamUV::timeout(TimeoutCallback cb, void* data, int time_ms) //{
{
    uv_loop_t* loop = uv_handle_get_loop((uv_handle_t*)this->mp_tcp);
    uv_timer_t* timer = new uv_timer_t();
    uv_timer_init(loop, timer);
    uv_handle_set_data((uv_handle_t*)timer, new __uv_timeout_state__(cb, data));
    uv_timer_start(timer, __uv_timeout_callback, time_ms, 0);
} //}

