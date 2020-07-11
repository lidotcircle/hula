#include "../include/stream_byprovider.h"

#include <type_traits>

#include <uv.h>


struct __cb_state: public CallbackPointer {
    EBStreamByProvider* _this;
    inline __cb_state(decltype(_this)_this): _this(_this) {}
};
#define GETSTATE(type) \
    type* msg = \
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data)); \
    assert(msg); \
    auto _this = msg->_this; \
    auto   run = msg->CanRun(); \
    auto   _cb = msg->_cb; \
    auto _data = msg->_data; \
    delete msg


void NotImplement() {assert(false && "not implement");}

bool EBStreamByProvider::bind(struct sockaddr* addr) {NotImplement(); return false;}
bool EBStreamByProvider::listen() {NotImplement(); return false;}
bool EBStreamByProvider::accept(void*, void*) {NotImplement(); return false;}

#define CHECK_SOCKET() \
    assert(this->m_info != nullptr); \
    assert(this->m_info->mp_provider != nullptr); \
    assert(this->m_info->m_id)


struct __write_cb_state: public __cb_state {
    EBStreamByProvider::WriteCallback _cb;
    void* _data;
    __write_cb_state(EBStreamByProvider* _this, decltype(_cb) cb, void* data): 
        __cb_state(_this), _cb(cb), _data(data) {}
};
void EBStreamByProvider::_write(ROBuf buf, WriteCallback cb, void* data) //{
{
    CHECK_SOCKET();
    assert(this->m_info->m_send_end == false);
    auto ptr = new __write_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->write(this->m_info->m_id, buf, write_callback, ptr);
} //}
/** [static] */
void EBStreamByProvider::write_callback(ROBuf buf, int status, void* data) //{
{
    GETSTATE(__write_cb_state);

    if(!run) {
        _cb(ROBuf(), -1, _data);
        return;
    }
    _this->remove_callback(msg);

    _cb(buf, status, _data);
} //}

struct __connect_cb_state: public __cb_state {
    EBStreamByProvider::ConnectCallback _cb;
    void* _data;
    __connect_cb_state(EBStreamByProvider* _this, decltype(_cb) cb, void* data): 
        __cb_state(_this), _cb(cb), _data(data) {}
};
bool EBStreamByProvider::connect(struct sockaddr* addr, ConnectCallback cb, void* data) //{
{
    CHECK_SOCKET();
    assert(this->m_info->m_send_end == false);

    auto ptr = new __connect_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->connect(this->m_info->m_id, addr, connect_callback, ptr);

    return true;
} //}
bool EBStreamByProvider::connect(uint32_t ipv4, uint16_t port, ConnectCallback cb, void* data) //{
{
    CHECK_SOCKET();
    assert(this->m_info->m_send_end == false);

    auto ptr = new __connect_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->connect(this->m_info->m_id, ipv4, port, connect_callback, ptr);

    return true;
} //}
bool EBStreamByProvider::connect(uint8_t  ipv6[16],          uint16_t port, ConnectCallback cb, void* data) //{
{
    CHECK_SOCKET();
    assert(this->m_info->m_send_end == false);

    auto ptr = new __connect_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->connect(this->m_info->m_id, ipv6, port, connect_callback, ptr);

    return true;
} //}
bool EBStreamByProvider::connect(const std::string& domname, uint16_t port, ConnectCallback cb, void* data) //{
{
    CHECK_SOCKET();
    assert(this->m_info->m_send_end == false);

    auto ptr = new __connect_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->connect(this->m_info->m_id, domname, port, connect_callback, ptr);

    return true;
} //}
bool EBStreamByProvider::connectINet6(const std::string& domname, uint16_t port, ConnectCallback cb, void* data) //{
{
    CHECK_SOCKET();
    assert(this->m_info->m_send_end == false);

    auto ptr = new __connect_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->connect(this->m_info->m_id, domname, port, connect_callback, ptr);

    return true;
} //}
/** [static] */
void EBStreamByProvider::connect_callback(int status, void* data) //{
{
    GETSTATE(__connect_cb_state);

    if(!run) {
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);

    _cb(status, _data);
} //}

void EBStreamByProvider::stop_read() //{
{
    CHECK_SOCKET();
    this->m_info->mp_provider->stopRead(this->m_info->m_id);
    this->m_stream_read = false;
} //}
void EBStreamByProvider::start_read() //{
{
    CHECK_SOCKET();
    this->m_info->mp_provider->startRead(this->m_info->m_id);
    this->m_stream_read = true;
} //}
bool EBStreamByProvider::in_read() //{
{
    return this->m_stream_read;
} //}

// getaddrinfo callback data //{
struct __getaddrinfo_cb_state: public __cb_state {
    EBStreamByProvider::GetAddrInfoCallback _cb;
    void* _data;
    __getaddrinfo_cb_state(EBStreamByProvider* _this, decltype(_cb) cb, void* data): 
        __cb_state(_this), _cb(cb), _data(data) {}
};
struct __getaddrinfoipv4_cb_state: public __cb_state {
    EBStreamByProvider::GetAddrInfoIPv4Callback _cb;
    void* _data;
    __getaddrinfoipv4_cb_state(EBStreamByProvider* _this, decltype(_cb) cb, void* data): 
        __cb_state(_this), _cb(cb), _data(data) {}
};
struct __getaddrinfoipv6_cb_state: public __cb_state {
    EBStreamByProvider::GetAddrInfoIPv6Callback _cb;
    void* _data;
    __getaddrinfoipv6_cb_state(EBStreamByProvider* _this, decltype(_cb) cb, void* data): 
        __cb_state(_this), _cb(cb), _data(data) {}
}; //}
void EBStreamByProvider::getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) //{
{
    CHECK_SOCKET();

    auto ptr = new __getaddrinfo_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->getaddrinfo(this->m_info->m_id, hostname, getaddrinfo_callback, ptr);
} //}
void EBStreamByProvider::getaddrinfoipv4 (const char* hostname, GetAddrInfoIPv4Callback cb, void* data) //{
{
    CHECK_SOCKET();

    auto ptr = new __getaddrinfoipv4_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->getaddrinfoIPv4(this->m_info->m_id, hostname, getaddrinfoipv4_callback, ptr);
} //}
void EBStreamByProvider::getaddrinfoipv6 (const char* hostname, GetAddrInfoIPv6Callback cb, void* data) //{
{
    CHECK_SOCKET();

    auto ptr = new __getaddrinfoipv6_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->getaddrinfoIPv6(this->m_info->m_id, hostname, getaddrinfoipv6_callback, ptr);
} //}
static void freeaddrinfo_k(struct addrinfo* ptr) //{
{
    while(ptr != nullptr) {
        auto n = ptr->ai_next;
        delete ptr;
        ptr = n;
    }
} //}
void EBStreamByProvider::getaddrinfo_callback(std::vector<uint32_t> ipv4, std::vector<uint8_t[16]> ipv6, int status, void* data) //{
{
    GETSTATE(__getaddrinfo_cb_state);

    if(!run) {
        _cb(nullptr, nullptr, -1, _data);
        return;
    }
    _this->remove_callback(msg);

    struct addrinfo *h = nullptr, *l = nullptr;
    for(auto& v: ipv4) {
        struct addrinfo* n = new struct addrinfo();
        n->ai_addrlen = sizeof(sockaddr_in);
        n->ai_family = AF_INET;
        n->ai_socktype = SOCK_STREAM;
        n->ai_addr = nullptr;
        if(l == nullptr) {
            h = n;
            l = n;
            l->ai_next = nullptr;
        } else {
            l->ai_next = n;
            l = n;
        }
    }

    if(h == nullptr)
        _cb(nullptr, nullptr, -1, _data);
    else
        _cb(h, freeaddrinfo_k, 0, _data);
} //}
void EBStreamByProvider::getaddrinfoipv4_callback(std::vector<uint32_t> ipv4, int status, void* data) //{
{
    GETSTATE(__getaddrinfoipv4_cb_state);

    if(!run) {
        _cb(0, -1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(ipv4.size() == 0) _cb(0, -1, _data);
    else _cb(ipv4.front(), status, _data);
} //}
void EBStreamByProvider::getaddrinfoipv6_callback(std::vector<uint8_t[16]> ipv6, int status, void* data) //{
{
    GETSTATE(__getaddrinfoipv6_cb_state);

    if(!run) {
        _cb(nullptr, -1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(ipv6.size() == 0) _cb(0, -1, _data);
    else _cb(ipv6.front(), status, _data);
} //}

struct __protect_ {StreamProvider* ppp;};
void* EBStreamByProvider::newUnderlyStream() //{
{
    CHECK_SOCKET();
    return new __protect_ {this->m_info->mp_provider};
} //}
void  EBStreamByProvider::releaseUnderlyStream(void* stream) //{
{
    delete static_cast<__protect_*>(stream);
    return;
} //}

EBStreamByProvider::EBStreamByProvider(StreamProvider* provider) //{
{
    this->m_info = new std::remove_pointer_t<decltype(this->m_info)>();
    this->m_info->mp_provider = provider;
    this->m_info->m_id = this->m_info->mp_provider->init(this);
    assert(this->m_info->m_id);
    this->m_stream_read = false;
    this->register_callback();
} //}
EBStreamByProvider::~EBStreamByProvider() //{
{
    if(this->hasStreamObject())
        this->release();
} //}

#define CASTTOTHIS() EBStreamByProvider* _this = dynamic_cast<decltype(_this)>(obj); assert(_this)
/** [static] */
void EBStreamByProvider::r_read_callback(EBStreamAbstraction* obj, ROBuf buf) //{
{
    CASTTOTHIS();
    _this->read_callback(buf, 0);
} //}
void EBStreamByProvider::r_error_callback(EBStreamAbstraction* obj) //{
{
    CASTTOTHIS();
    _this->read_callback(ROBuf(), -1);
} //}
void EBStreamByProvider::r_end_callback(EBStreamAbstraction* obj) //{
{
    CASTTOTHIS();
    _this->end_signal();
} //}
void EBStreamByProvider::r_shouldstartwrite_callback(EBStreamAbstraction* obj) //{
{
    CASTTOTHIS();
    _this->should_start_write();
} //}
void EBStreamByProvider::r_shouldstopwrite_callback(EBStreamAbstraction* obj) //{
{
    CASTTOTHIS();
    _this->should_stop_write();
} //}

void EBStreamByProvider::register_callback() //{
{
    this->m_info->mp_provider->registerReadCallback(this->m_info->m_id, r_read_callback);
    this->m_info->mp_provider->registerErrorCallback(this->m_info->m_id, r_error_callback);
    this->m_info->mp_provider->registerEndCallback(this->m_info->m_id, r_end_callback);
    this->m_info->mp_provider->registerShouldStartWriteCallback(this->m_info->m_id, r_shouldstartwrite_callback);
    this->m_info->mp_provider->registerShouldStopWriteCallback(this->m_info->m_id, r_shouldstopwrite_callback);
} //}

struct __end_cb_state: public __cb_state {
    EBStreamByProvider::ShutdownCallback _cb;
    void* _data;
    __end_cb_state(EBStreamByProvider* _this, decltype(_cb) cb, void* data): 
        __cb_state(_this), _cb(cb), _data(data) {}
};
void EBStreamByProvider::shutdown(ShutdownCallback cb, void* data) //{
{
    CHECK_SOCKET();
    assert(this->m_info->m_send_end == false);
    this->m_info->m_send_end = true;
    auto ptr = new __end_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->end(this->m_info->m_id, shutdown_callback, ptr);
} //}
/** [static] */
void EBStreamByProvider::shutdown_callback(ROBuf buf, int status, void* data) //{
{
    GETSTATE(__end_cb_state);

    if(!run) {
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);

    _cb(status, _data);
} //}

void* EBStreamByProvider::transfer() //{
{
    CHECK_SOCKET();
    this->stop_read();
    auto ret = this->m_info;
    this->m_info = nullptr;

    return ret;
} //}
void  EBStreamByProvider::regain(void* data) //{
{
    assert(this->m_info == nullptr);
    struct __info_type* info =
        dynamic_cast<decltype(info)>(static_cast<__virtualbase*>(data));
    assert(info);

    this->m_info = info;
    this->start_read();
} //}

void  EBStreamByProvider::release() //{
{
    CHECK_SOCKET();
    this->m_info->mp_provider->closeStream(this->m_info->m_id);
    delete this->m_info;
    this->m_info = nullptr;
} //}
bool  EBStreamByProvider::hasStreamObject() //{
{
    return this->m_info != nullptr;
} //}

void EBStreamByProvider::timeout(TimeoutCallback cb, void* data, int time) //{
{
    CHECK_SOCKET();
    this->m_info->mp_provider->timeout(cb, data, time);
} //}

