#include "../include/stream_libuv.h"
#include "../include/config.h"
#include "../include/logger.h"

#include "stream_libuv_cb_data.h"

#include <assert.h>
#include <string.h>

#define DEFAULT_BACKLOG       100

#define DEBUG(all...) __logger->debug(all)


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
    DEBUG("call %s", FUNCNAME);
    assert(cb != nullptr);
    uv_buf_t* uv_buf = new uv_buf_t();
    uv_buf->base = buf.__base();
    uv_buf->len  = buf.size();

    uv_write_t* req = new uv_write_t();
    auto ptr = new EBStreamUV$_write$uv_write(this, buf, uv_buf, cb, data);
    uv_req_set_data((uv_req_t*)req, ptr);

    this->m_stat_traffic_out += buf.size();
    uv_write(req, (uv_stream_t*)this->mp_tcp, uv_buf, 1, EBStreamUV::uv_write_callback);
} //}
/** [static] */
void EBStreamUV::uv_write_callback(uv_write_t* req, int status) //{
{
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
    assert(this->mp_tcp != nullptr);
    return uv_tcp_bind(this->mp_tcp, addr, 0) < 0 ? false : true;
} //}
bool EBStreamUV::listen() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->mp_tcp != nullptr);
    return uv_listen((uv_stream_t*)this->mp_tcp, DEFAULT_BACKLOG, uv_connection_callback) < 0 ? false : true;
} //}
/** [static] */
void EBStreamUV::uv_connection_callback(uv_stream_t* stream, int status) //{
{
    DEBUG("call %s", FUNCNAME);
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
        _this->on_connection(UNST(nullptr));
    } else {
        _this->on_connection(UNST(new __UnderlyingStreamUV(_this->getType(), newcon)));
    }
} //}

#include "../include/utils.h"
bool EBStreamUV::connect(struct sockaddr* addr, ConnectCallback cb, void* data) //{
{
    __logger->info("call %s=(%s:%d)", FUNCNAME, 
            ip4_to_str(((sockaddr_in*)addr)->sin_addr.s_addr), 
            k_ntohs(((sockaddr_in*)addr)->sin_port));
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
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
    sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(ipv4);
    addr.sin_port        = htons(port);
    return this->connect((sockaddr*)&addr, cb, data);
} //}
bool EBStreamUV::connect(uint8_t ipv6[16], uint16_t port, ConnectCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
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
                ((sockaddr_in*)m)->sin_port = htons(_port);
                break;
            }
        }
    }

    if(m == nullptr) {
        for(a=res;a!=nullptr;a=a->ai_next) {
            if(a->ai_family == AF_INET6) {
                m = a->ai_addr;
                ((sockaddr_in6*)m)->sin6_port = htons(_port);
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
    DEBUG("call %s", FUNCNAME);
    auto ptr = new __ppp(this, cb, data, port);
    ptr->_force_ipv6 = false;
    this->add_callback(ptr);

    this->getaddrinfo(addr.c_str(), getaddrinfo_callback, ptr);
    return true;
} //}
bool EBStreamUV::connectINet6(const std::string& addr, uint16_t port, ConnectCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    auto ptr = new __ppp(this, cb, data, port);
    ptr->_force_ipv6 = true;
    this->add_callback(ptr);

    this->getaddrinfo(addr.c_str(), getaddrinfo_callback, ptr);
    return true;
} //}

/** wrapper of uv_read_start() and uv_read_stop() */
void EBStreamUV::stop_read() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_stream_read == true);
    uv_read_stop((uv_stream_t*)this->mp_tcp);
    this->m_stream_read = false;
} //}
void EBStreamUV::start_read() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_stream_read == false);
    uv_read_start((uv_stream_t*)this->mp_tcp, malloc_cb, EBStreamUV::uv_stream_read_callback);
    this->m_stream_read = true;
} //}
/** [static] */
void EBStreamUV::uv_stream_read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    DEBUG("call %s", FUNCNAME);
    EBStreamUV* _this = static_cast<decltype(_this)>(uv_handle_get_data((uv_handle_t*)stream));

    if(nread <= 0) {
        free(buf->base);
        if(nread < 0) {
            _this->read_callback(ROBuf(), -1);
        } else {
            _this->end_signal();
        }
        return;
    }

    ROBuf rbuf(buf->base, nread, 0, free);
    _this->m_stat_traffic_in += rbuf.size(); // FIXME invalid read ?????? rediculous, ahah
    _this->read_callback(rbuf, 0);
} //}

/** read state of the stream */
bool EBStreamUV::in_read() //{
{
    DEBUG("call %s", FUNCNAME);
    return this->m_stream_read;
} //}

void EBStreamUV::getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
    uv_freeaddrinfo(addr);
} //}

/** dns utils */
static void getaddrinfo_callback_for_getaddrinfoipv4(struct addrinfo* res, void(*__freeaddrinfo)(struct addrinfo*), int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
    this->getaddrinfo(hostname, getaddrinfo_callback_for_getaddrinfoipv4, new std::pair<GetAddrInfoIPv4Callback, void*>(cb, data));
} //}
static void getaddrinfo_callback_for_getaddrinfoipv6(struct addrinfo* res, void(*__freeaddrinfo)(struct addrinfo*), int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
    this->getaddrinfo(hostname, getaddrinfo_callback_for_getaddrinfoipv6, new std::pair<GetAddrInfoIPv6Callback, void*>(cb, data));
} //}

EBStreamAbstraction::UNST EBStreamUV::newUnderlyStream() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->mp_tcp != nullptr);
    uv_loop_t* loop = uv_handle_get_loop((uv_handle_t*)this->mp_tcp);
    uv_tcp_t* stream = new uv_tcp_t();
    uv_tcp_init(loop, stream);
    return UNST(new __UnderlyingStreamUV(this->getType(), stream));
} //}
void EBStreamUV::releaseUnderlyStream(UNST ptr) //{
{
    DEBUG("call %s", FUNCNAME);
    __UnderlyingStreamUV* pp = dynamic_cast<decltype(pp)>(ptr.get());
    assert(pp); assert(pp->getType() == this->getType());
    uv_tcp_t* tcp = pp->getStream();
    uv_close((uv_handle_t*)tcp, delete_closed_handle<decltype(tcp)>);
} //}
bool  EBStreamUV::accept(UNST stream) //{
{
    DEBUG("call %s", FUNCNAME);
    __UnderlyingStreamUV* stream__ = dynamic_cast<decltype(stream__)>(stream.get()); assert(stream__);
    assert(stream__->getType() == this->getType());
    return uv_accept((uv_stream_t*)(this->mp_tcp), (uv_stream_t*)(stream__->getStream())) < 0 ?
        false :
        true;
} //}
bool  EBStreamUV::accept(EBStreamUV* stream) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->mp_tcp); assert(stream && stream->mp_tcp);
    return uv_accept((uv_stream_t*)(this->mp_tcp), (uv_stream_t*)(stream->mp_tcp)) < 0 ?
        false :
        true;
} //}

EBStreamUV::EBStreamUV(uv_tcp_t* tcp) //{
{
    DEBUG("call %s", FUNCNAME);
    this->mp_tcp = tcp;
    if(this->mp_tcp != nullptr)
        uv_handle_set_data((uv_handle_t*)this->mp_tcp, this);
    this->m_stream_read = false;

    this->recalculatespeed();
} //}
EBStreamUV::EBStreamUV(UNST tcp) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(tcp->getType() == StreamType::LIBUV);
    this->mp_tcp = EBStreamUV::getStreamFromWrapper(tcp);
    if(this->mp_tcp != nullptr)
        uv_handle_set_data((uv_handle_t*)this->mp_tcp, this);
    this->m_stream_read = false;

    this->recalculatespeed();
} //}
EBStreamUV::~EBStreamUV() //{
{
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
    uv_shutdown_t* req = new uv_shutdown_t();
    auto ptr = new EBStreamUV$shutdown$uv_shutdown(cb, data);
    uv_req_set_data((uv_req_t*)req, ptr);
    uv_shutdown(req, (uv_stream_t*)this->mp_tcp, shutdown_callback);
} //}

bool  EBStreamUV::hasStreamObject() //{
{
    DEBUG("call %s", FUNCNAME);
    return this->mp_tcp != nullptr;
} //}
void EBStreamUV::release() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->mp_tcp != nullptr);
    if(this->in_read()) this->stop_read();
    uv_close((uv_handle_t*)this->mp_tcp, delete_closed_handle<decltype(this->mp_tcp)>);
    this->mp_tcp = nullptr;
} //}

EBStreamAbstraction::UNST EBStreamUV::transfer() //{
{
    DEBUG("call %s", FUNCNAME);
    if(this->in_read()) this->stop_read();
    auto stream = this->mp_tcp;
    this->mp_tcp = nullptr;
    return UNST(new __UnderlyingStreamUV(this->getType(), stream));
} //}
void  EBStreamUV::regain(UNST stream) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->in_read() == false);
    assert(this->mp_tcp == nullptr);
    assert(stream->getType() == this->getType());
    __UnderlyingStreamUV* ss = dynamic_cast<decltype(ss)>(stream.get()); assert(ss);
    this->mp_tcp = static_cast<decltype(this->mp_tcp)>(ss->getStream());
    uv_handle_set_data((uv_handle_t*)this->mp_tcp, this);
} //}


std::string EBStreamUV::remote_addr()//{
{
    static char storage[256];
    memset(storage, 0, sizeof(storage));
    struct sockaddr_storage addr;
    int len = 0;
    if(this->mp_tcp == nullptr) return "";
    if(uv_tcp_getpeername(this->mp_tcp, (struct sockaddr*)&addr, &len) < 0) return "";
    if(uv_inet_ntop(addr.ss_family, &addr, storage, sizeof(storage)) < 0)   return "";
    return storage;
} //}
uint16_t EBStreamUV::remote_port() //{
{
    struct sockaddr_storage addr;
    int len = 0;
    if(this->mp_tcp == nullptr) return 0;
    if(uv_tcp_getpeername(this->mp_tcp, (struct sockaddr*)&addr, &len) < 0) return 0;

    if(addr.ss_family == AF_INET) {
        struct sockaddr_in* addr_in = (decltype(addr_in))&addr;
        return k_ntohs(addr_in->sin_port);
    } else if(addr.ss_family == AF_INET6) {
        struct sockaddr_in6* addr_in6 = (decltype(addr_in6))&addr;
        return k_ntohs(addr_in6->sin6_port);
    } else {
        return 0;
    }
} //}
std::string EBStreamUV::local_addr()//{
{
    static char storage[256];
    memset(storage, 0, sizeof(storage));
    struct sockaddr_storage addr;
    int len = 0;
    if(this->mp_tcp == nullptr) return "";
    if(uv_tcp_getsockname(this->mp_tcp, (struct sockaddr*)&addr, &len) < 0) return "";
    if(uv_inet_ntop(addr.ss_family, &addr, storage, sizeof(storage)) < 0)   return "";
    return storage;
} //}
uint16_t EBStreamUV::local_port() //{
{
    struct sockaddr_storage addr;
    int len = 0;
    if(this->mp_tcp == nullptr) return 0;
    if(uv_tcp_getpeername(this->mp_tcp, (struct sockaddr*)&addr, &len) < 0) return 0;

    if(addr.ss_family == AF_INET) {
        struct sockaddr_in* addr_in = (decltype(addr_in))&addr;
        return k_ntohs(addr_in->sin_port);
    } else if(addr.ss_family == AF_INET6) {
        struct sockaddr_in6* addr_in6 = (decltype(addr_in6))&addr;
        return k_ntohs(addr_in6->sin6_port);
    } else {
        return 0;
    }
} //}

StreamType EBStreamUV::getType() {return StreamType::LIBUV;}

/** [static] */
uv_tcp_t* EBStreamUV::getStreamFromWrapper(UNST wstream) //{
{
    assert(wstream->getType() == StreamType::LIBUV);
    __UnderlyingStreamUV* stream = dynamic_cast<decltype(stream)>(wstream.get());
    assert(stream);
    return stream->getStream();
} //}
EBStreamAbstraction::UNST EBStreamUV::getWrapperFromStream(uv_tcp_t* stream) //{
{
    return UNST(new __UnderlyingStreamUV(StreamType::LIBUV, stream));
} //}

uv_loop_t* EBStreamUV::get_uv_loop() //{
{
    assert(this->mp_tcp); 
    return uv_handle_get_loop((uv_handle_t*)this->mp_tcp);
} //}

struct __uv_timeout_state__ {
    EBStreamAbstraction::TimeoutCallback _cb;
    void* _data; 
    __uv_timeout_state__(EBStreamAbstraction::TimeoutCallback cb, void* data): _cb(cb), _data(data) {}
};
static void __uv_timeout_callback(uv_timer_t* timer) //{
{
//    DEBUG("call %s", FUNCNAME);
    __uv_timeout_state__* msg = static_cast<decltype(msg)>(uv_handle_get_data((uv_handle_t*)timer));
    uv_timer_stop(timer);
    auto cb = msg->_cb;
    auto data = msg->_data;
    delete msg;

    cb(data);

    uv_close((uv_handle_t*)timer, delete_closed_handle<decltype(timer)>);
} //}
bool EBStreamUV::timeout(TimeoutCallback cb, void* data, int time_ms) //{
{
//    DEBUG("call %s", FUNCNAME);
    if(this->mp_tcp == nullptr) return false;
    uv_loop_t* loop = uv_handle_get_loop((uv_handle_t*)this->mp_tcp);
    uv_timer_t* timer = new uv_timer_t();
    uv_timer_init(loop, timer);
    uv_handle_set_data((uv_handle_t*)timer, new __uv_timeout_state__(cb, data));
    uv_timer_start(timer, __uv_timeout_callback, time_ms, 0);
    return true;
} //}

