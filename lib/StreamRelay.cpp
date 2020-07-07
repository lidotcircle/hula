#include "../include/StreamRelay.h"
#include "../include/config.h"


/** constructor of StreamRelay */
StreamRelay::StreamRelay(): m_a_drain_listener_reg(), m_b_drain_listener_reg() //{
{
    __logger->debug("call %s", FUNCNAME);
    this->mp_stream_a = nullptr;
    this->mp_stream_b = nullptr;
    this->m_a_start_read = false;
    this->m_b_start_read = false;
    this->m_a_end = false;
    this->m_b_end = false;
}
//}

void StreamRelay::register_a_listener() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->mp_stream_a != nullptr);
    this->mp_stream_a->on("data", a_data_listener);
    this->mp_stream_a->on("end", a_end_listener);
    this->mp_stream_a->on("error", a_error_listener);
    this->m_a_drain_listener_reg = this->mp_stream_a->on("drain", a_drain_listener);
} //}
void StreamRelay::register_b_listener() //{
{
    __logger->debug("call %s", FUNCNAME);
    this->mp_stream_b->on("data", b_data_listener);
    this->mp_stream_b->on("end", b_end_listener);
    this->mp_stream_b->on("error", b_error_listener);
    this->m_b_drain_listener_reg = this->mp_stream_b->on("drain", b_drain_listener);
} //}

#define EVENTARGS EventEmitter*obj, const std::string& event, EventArgs::Base* aaa
#define DOIT(ename, dt) \
                        __logger->debug("call %s", FUNCNAME); \
                        EBStreamObject* _streamobj = dynamic_cast<decltype(_streamobj)>(obj); assert(_streamobj); \
                        StreamRelay* _this     = static_cast<decltype(_this)>(_streamobj->fetchPtr()); assert(_this); \
                        EBStreamObject::dt *args   = dynamic_cast<decltype(args)>(aaa);  assert(args); \
                        assert(event == ename);

void StreamRelay::a_data_listener(EVENTARGS) //{
{
    DOIT("data", DataArgs);
    auto buf = args->_buf;

    auto rv = _this->mp_stream_b->write(buf);
    if(rv < 0 && _this->m_a_start_read)
        _this->__stop_a_to_b();
} //}
void StreamRelay::b_data_listener(EVENTARGS) //{
{
    DOIT("data", DataArgs);
    auto buf = args->_buf;

    auto rv = _this->mp_stream_a->write(buf);
    if(rv < 0 && _this->m_b_start_read)
        _this->__stop_b_to_a();
} //}

void StreamRelay::a_drain_listener(EVENTARGS) //{
{
    DOIT("drain", DrainArgs);
    if(!_this->m_b_start_read)
        _this->__relay_b_to_a();
} //}
void StreamRelay::b_drain_listener(EVENTARGS) //{
{
    DOIT("drain", DrainArgs);
    if(!_this->m_a_start_read)
        _this->__relay_a_to_b();
} //}

void StreamRelay::a_end_listener(EVENTARGS) //{
{
    DOIT("end", EndArgs);

    if(_this->m_a_end) {
        _this->StreamA()->emit("error", new EBStreamObject::ErrorArgs("double end"));
    } else {
        _this->mp_stream_b->end();
        _this->m_a_end = true;
        if(_this->m_b_end)
            _this->__close();
    }
} //}
void StreamRelay::b_end_listener(EVENTARGS) //{
{
    DOIT("end", EndArgs);

    if(_this->m_b_end) {
        _this->StreamB()->emit("error", new EBStreamObject::ErrorArgs("double end"));
    } else {
        _this->mp_stream_a->end();
        _this->m_b_end = true;
        if(_this->m_a_end)
            _this->__close();
    }
} //}

void StreamRelay::a_error_listener(EVENTARGS) //{
{
    DOIT("error", ErrorArgs);

    _this->__close();
} //}
void StreamRelay::b_error_listener(EVENTARGS) //{
{
    DOIT("error", ErrorArgs);

    _this->__close();
} //}

#undef EVENTARGS
#undef DOIT

/** start dual direction tcp relay */
void StreamRelay::start_relay() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->mp_stream_a != nullptr);
    assert(this->mp_stream_b != nullptr);
    this->register_a_listener();
    this->register_b_listener();
    this->__relay_a_to_b();
    this->__relay_b_to_a();
} //}

/** As name suggested */
void StreamRelay::__relay_a_to_b() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_a_start_read == false);
    this->mp_stream_a->startRead();
    this->m_a_start_read = true;
} //}
void StreamRelay::__relay_b_to_a() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_b_start_read == false);
    this->mp_stream_b->startRead();
    this->m_b_start_read = true;
} //}
void StreamRelay::__stop_a_to_b() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_a_start_read);
    this->mp_stream_a->stopRead();
    this->m_a_start_read = false;
} //}
void StreamRelay::__stop_b_to_a() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_b_start_read);
    this->mp_stream_b->stopRead();
    this->m_b_start_read = false;
} //}

void StreamRelay::setStreamA(EBStreamObject* stream) //{
{
    assert(stream->fetchPtr() == nullptr);
    assert(this->mp_stream_a == nullptr); 
    this->mp_stream_a = stream;
    this->mp_stream_a->storePtr(this);
} //}
void StreamRelay::setStreamB(EBStreamObject* stream) //{
{
    assert(stream->fetchPtr() == nullptr);
    assert(this->mp_stream_b == nullptr); 
    this->mp_stream_b = stream;
    this->mp_stream_b->storePtr(this);
} //}
EBStreamObject* StreamRelay::StreamA() {return this->mp_stream_a;}
EBStreamObject* StreamRelay::StreamB() {return this->mp_stream_b;}

StreamRelay::~StreamRelay() //{
{
    if(this->mp_stream_a) delete this->mp_stream_a;
    if(this->mp_stream_b) delete this->mp_stream_b;
} //}

