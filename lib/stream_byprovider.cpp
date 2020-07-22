#include "../include/stream_byprovider.h"
#include "../include/config.h"

#include <type_traits>

#include <uv.h>


#define DEBUG(all...) __logger->debug(all)


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
bool EBStreamByProvider::accept(UNST) {NotImplement(); return false;}

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
    DEBUG("call %s", FUNCNAME);
    CHECK_SOCKET();
    assert(this->m_info->m_send_end == false);
    auto ptr = new __write_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_stat_traffic_out += buf.size();
    this->m_info->mp_provider->write(this->m_info->m_id, buf, write_callback, ptr);
} //}
/** [static] */
void EBStreamByProvider::write_callback(ROBuf buf, int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    GETSTATE(__write_cb_state);

    if(!run) {
        _cb(ROBuf(), -1, _data);
        return;
    }
    _this->remove_callback(msg);

    _cb(buf, status, _data);
} //}

StreamProvider* EBStreamByProvider::getProvider() //{
{
    if(this->m_info == nullptr) return nullptr;
    return this->m_info->mp_provider;
} //}

struct __connect_cb_state: public __cb_state {
    EBStreamByProvider::ConnectCallback _cb;
    void* _data;
    __connect_cb_state(EBStreamByProvider* _this, decltype(_cb) cb, void* data): 
        __cb_state(_this), _cb(cb), _data(data) {}
};
bool EBStreamByProvider::connect(struct sockaddr* addr, ConnectCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    CHECK_SOCKET();
    assert(this->m_info->m_send_end == false);

    auto ptr = new __connect_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->connect(this->m_info->m_id, addr, connect_callback, ptr);

    return true;
} //}
bool EBStreamByProvider::connect(uint32_t ipv4, uint16_t port, ConnectCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    CHECK_SOCKET();
    assert(this->m_info->m_send_end == false);

    auto ptr = new __connect_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->connect(this->m_info->m_id, ipv4, port, connect_callback, ptr);

    return true;
} //}
bool EBStreamByProvider::connect(uint8_t  ipv6[16],          uint16_t port, ConnectCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    CHECK_SOCKET();
    assert(this->m_info->m_send_end == false);

    auto ptr = new __connect_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->connect(this->m_info->m_id, ipv6, port, connect_callback, ptr);

    return true;
} //}
bool EBStreamByProvider::connect(const std::string& domname, uint16_t port, ConnectCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    CHECK_SOCKET();
    assert(this->m_info->m_send_end == false);

    auto ptr = new __connect_cb_state(this, cb, data); // FIXME LOSS
    this->add_callback(ptr);
    this->m_info->mp_provider->connect(this->m_info->m_id, domname, port, connect_callback, ptr);

    return true;
} //}
bool EBStreamByProvider::connectINet6(const std::string& domname, uint16_t port, ConnectCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
    CHECK_SOCKET();
    this->m_info->mp_provider->stopRead(this->m_info->m_id);
    this->m_stream_read = false;
} //}
void EBStreamByProvider::start_read() //{
{
    DEBUG("call %s", FUNCNAME);
    CHECK_SOCKET();
    this->m_info->mp_provider->startRead(this->m_info->m_id);
    this->m_stream_read = true;
} //}
bool EBStreamByProvider::in_read() //{
{
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
    CHECK_SOCKET();

    auto ptr = new __getaddrinfo_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->getaddrinfo(this->m_info->m_id, hostname, getaddrinfo_callback, ptr);
} //}
void EBStreamByProvider::getaddrinfoipv4 (const char* hostname, GetAddrInfoIPv4Callback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    CHECK_SOCKET();

    auto ptr = new __getaddrinfoipv4_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->getaddrinfoIPv4(this->m_info->m_id, hostname, getaddrinfoipv4_callback, ptr);
} //}
void EBStreamByProvider::getaddrinfoipv6 (const char* hostname, GetAddrInfoIPv6Callback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    CHECK_SOCKET();

    auto ptr = new __getaddrinfoipv6_cb_state(this, cb, data);
    this->add_callback(ptr);
    this->m_info->mp_provider->getaddrinfoIPv6(this->m_info->m_id, hostname, getaddrinfoipv6_callback, ptr);
} //}
static void freeaddrinfo_k(struct addrinfo* ptr) //{
{
    DEBUG("call %s", FUNCNAME);
    while(ptr != nullptr) {
        auto n = ptr->ai_next;
        delete ptr;
        ptr = n;
    }
} //}
void EBStreamByProvider::getaddrinfo_callback(std::vector<uint32_t> ipv4, std::vector<uint8_t[16]> ipv6, int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
    GETSTATE(__getaddrinfoipv6_cb_state);

    if(!run) {
        _cb(nullptr, -1, _data);
        return;
    }
    _this->remove_callback(msg);

    if(ipv6.size() == 0) _cb(0, -1, _data);
    else _cb(ipv6.front(), status, _data);
} //}

EBStreamAbstraction::UNST EBStreamByProvider::newUnderlyStream() //{
{
    DEBUG("call %s", FUNCNAME);
    CHECK_SOCKET();
    __info_type* wrapper = new __info_type();
    auto id = this->m_info->mp_provider->init(nullptr); // TODO
    wrapper->mp_provider = this->m_info->mp_provider;
    wrapper->m_id = id;
    wrapper->m_send_end = false;
    return UNST(new __UnderlyingStreamProvider(this->getType(), wrapper));
} //}
void  EBStreamByProvider::releaseUnderlyStream(UNST stream) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(stream->getType() == this->getType());
    __UnderlyingStreamProvider* ptr =  dynamic_cast<decltype(ptr)>(stream.get()); assert(ptr);
    auto info = ptr->getStream();
    info->mp_provider->closeStream(info->m_id);
    return;
} //}

EBStreamByProvider::EBStreamByProvider(StreamProvider* provider) //{
{
    DEBUG("call %s", FUNCNAME);
    this->m_info = new std::remove_pointer_t<decltype(this->m_info)>();
    this->m_info->mp_provider = provider;
    this->m_info->m_id = this->m_info->mp_provider->init(this);
    assert(this->m_info->m_id);
    this->m_stream_read = false;
    this->register_callback();

    this->m_stat_local_port = 0;
    this->m_stat_remote_port = 0;
    this->m_stat_local_address = "";
    this->m_stat_remote_address = "";
    this->recalculatespeed();
} //}
EBStreamByProvider::~EBStreamByProvider() //{
{
    DEBUG("call %s", FUNCNAME);
    if(this->hasStreamObject())
        this->release();
} //}

#define CASTTOTHIS() EBStreamByProvider* _this = dynamic_cast<decltype(_this)>(obj); assert(_this)
/** [static] */
void EBStreamByProvider::r_read_callback(EBStreamAbstraction* obj, ROBuf buf) //{
{
    DEBUG("call %s", FUNCNAME);
    CASTTOTHIS();
    _this->m_stat_traffic_in += buf.size();
    _this->read_callback(buf, 0);
} //}
void EBStreamByProvider::r_error_callback(EBStreamAbstraction* obj) //{
{
    DEBUG("call %s", FUNCNAME);
    CASTTOTHIS();
    _this->read_callback(ROBuf(), -1);
} //}
void EBStreamByProvider::r_end_callback(EBStreamAbstraction* obj) //{
{
    DEBUG("call %s", FUNCNAME);
    CASTTOTHIS();
    _this->end_signal();
} //}
void EBStreamByProvider::r_shouldstartwrite_callback(EBStreamAbstraction* obj) //{
{
    DEBUG("call %s", FUNCNAME);
    CASTTOTHIS();
    _this->should_start_write();
} //}
void EBStreamByProvider::r_shouldstopwrite_callback(EBStreamAbstraction* obj) //{
{
    DEBUG("call %s", FUNCNAME);
    CASTTOTHIS();
    _this->should_stop_write();
} //}

void EBStreamByProvider::register_callback() //{
{
    DEBUG("call %s", FUNCNAME);
    this->m_info->mp_provider->registerReadCallback(this->m_info->m_id, r_read_callback);
    this->m_info->mp_provider->registerErrorCallback(this->m_info->m_id, r_error_callback);
    this->m_info->mp_provider->registerCloseCallback(this->m_info->m_id, r_error_callback);
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
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
    GETSTATE(__end_cb_state);

    if(!run) {
        _cb(-1, _data);
        return;
    }
    _this->remove_callback(msg);

    _cb(status, _data);
} //}

EBStreamAbstraction::UNST EBStreamByProvider::transfer() //{
{
    DEBUG("call %s", FUNCNAME);
    CHECK_SOCKET();
    this->stop_read();
    auto stream = this->m_info;
    this->m_info = nullptr;

    stream->mp_provider->changeOwner(stream->m_id, nullptr);
    return UNST(new __UnderlyingStreamProvider(this->getType(), stream));
} //}
void  EBStreamByProvider::regain(UNST stream) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(stream->getType() == this->getType());
    __UnderlyingStreamProvider* msg =
        dynamic_cast<decltype(msg)>(stream.get());
    assert(msg);

    assert(this->m_info == nullptr);
    struct __info_type* info = msg->getStream();
    info->mp_provider->changeOwner(info->m_id, this);
    assert(info);

    this->m_info = info;
    this->start_read();
} //}

void  EBStreamByProvider::release() //{
{
    DEBUG("call %s", FUNCNAME);
    CHECK_SOCKET();
    this->m_info->mp_provider->closeStream(this->m_info->m_id);
    delete this->m_info;
    this->m_info = nullptr;
} //}
bool  EBStreamByProvider::hasStreamObject() //{
{
    DEBUG("call %s", FUNCNAME);
    return this->m_info != nullptr;
} //}

bool EBStreamByProvider::timeout(TimeoutCallback cb, void* data, int time) //{
{
    DEBUG("call %s", FUNCNAME);
    if(this->m_info == nullptr) return false;
    CHECK_SOCKET();
    this->m_info->mp_provider->timeout(cb, data, time);
    return true;
} //}



StreamType EBStreamObjectKProxyMultiplexerProvider::getType() {return StreamType::KPROXY_MULTIPLEXER;}
EBStreamObject* EBStreamObjectKProxyMultiplexerProvider::NewStreamObject(UNST stream) //{
{
    this->releaseUnderlyStream(stream);
    return new EBStreamObjectKProxyMultiplexerProvider(this->getProvider(), NEW_STREAM_OBJECT_BUFFER_SIZE); // TODO
} //}
bool EBStreamObjectKProxyMultiplexerProvider::accept(EBStreamObject*) {NotImplement(); return false;}

