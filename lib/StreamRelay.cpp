#include "../include/StreamRelay.h"
#include "../include/config.h"

#include <random>
static std::default_random_engine random_engine;
static std::uniform_int_distribution<int> random_dist;


#define DEBUG(all...) __logger->debug(all)


struct _stream_realy_state: public CallbackPointer {
    StreamRelay* _this;
    _stream_realy_state(StreamRelay* _this): _this(_this) {}
};


/** constructor of StreamRelay */
StreamRelay::StreamRelay(): m_a_drain_listener_reg(), m_b_drain_listener_reg() //{
{
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
    assert(this->mp_stream_a != nullptr);
    this->mp_stream_a->on("data", a_data_listener);
    this->mp_stream_a->on("end", a_end_listener);
    this->mp_stream_a->on("error", a_error_listener);

    this->mp_stream_a->on("shouldStartWrite", a_shouldstartwrite_listener);
    this->mp_stream_a->on("shouldStopWrite",  a_shouldstopwrite_listener);

    this->m_a_drain_listener_reg = this->mp_stream_a->on("drain", a_drain_listener);
} //}
void StreamRelay::register_b_listener() //{
{
    DEBUG("call %s", FUNCNAME);
    this->mp_stream_b->on("data", b_data_listener);
    this->mp_stream_b->on("end", b_end_listener);
    this->mp_stream_b->on("error", b_error_listener);

    this->mp_stream_a->on("shouldStartWrite", b_shouldstartwrite_listener);
    this->mp_stream_a->on("shouldStopWrite",  b_shouldstopwrite_listener);

    this->m_b_drain_listener_reg = this->mp_stream_b->on("drain", b_drain_listener);
} //}

#define EVENTARGS EventEmitter*obj, const std::string& event, EventArgs::Base* aaa
#define DOIT(ename, dt) \
                        DEBUG("call %s", FUNCNAME); \
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

void StreamRelay::a_shouldstartwrite_listener(EVENTARGS) //{
{
    DOIT("shouldStartWrite", ShouldStartWriteArgs);

    if(!_this->m_b_start_read)
        _this->__relay_b_to_a();
} //}
void StreamRelay::b_shouldstartwrite_listener(EVENTARGS) //{
{
    DOIT("shouldStartWrite", ShouldStartWriteArgs);

    if(!_this->m_a_start_read)
        _this->__relay_a_to_b();
} //}

struct _stream_realy_waitstart_state: public _stream_realy_state {
    int m_prev;
    inline _stream_realy_waitstart_state(StreamRelay* _this, int prev): _stream_realy_state(_this), m_prev(prev) {}
};
void StreamRelay::a_shouldstopwrite_listener(EVENTARGS) //{
{
    DOIT("shouldStopWrite", ShouldStopWriteArgs);

    if(_this->m_b_start_read) {
        _this->__stop_b_to_a();
        auto ptr = new _stream_realy_waitstart_state(_this, _this->m_b_random);
        _this->add_callback(ptr);
        _this->StreamB()->SetTimeout(__wait_b_start_read, ptr, MAXIMUM_SHOULD_START_WAIT_TIMEOUT);
    }
} //}
void StreamRelay::b_shouldstopwrite_listener(EVENTARGS) //{
{
    DOIT("shouldStopWrite", ShouldStopWriteArgs);

    if(_this->m_a_start_read) {
        _this->__stop_a_to_b();
        auto ptr = new _stream_realy_waitstart_state(_this, _this->m_a_random);
        _this->add_callback(ptr);
        _this->StreamA()->SetTimeout(__wait_a_start_read, ptr, MAXIMUM_SHOULD_START_WAIT_TIMEOUT);
    }
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

/** [static] */
void StreamRelay::__wait_a_start_read(void* data) //{
{
    _stream_realy_waitstart_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto _prev = msg->m_prev;
    auto run   = msg->CanRun();
    delete msg;
    
    if(!run) return;
    _this->remove_callback(msg);

    if(_this->m_a_random == _prev)
        _this->__close();
} //}
void StreamRelay::__wait_b_start_read(void* data) //{
{
    _stream_realy_waitstart_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto _prev = msg->m_prev;
    auto run   = msg->CanRun();
    delete msg;
    
    if(!run) return;
    _this->remove_callback(msg);

    if(_this->m_b_random == _prev)
        _this->__close();
} //}

/** start dual direction tcp relay */
void StreamRelay::start_relay() //{
{
    DEBUG("call %s", FUNCNAME);
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
    DEBUG("call %s", FUNCNAME);
    assert(this->m_a_start_read == false);
    this->mp_stream_a->startRead();
    this->m_a_start_read = true;
    this->m_a_random = random_dist(random_engine);
} //}
void StreamRelay::__relay_b_to_a() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_b_start_read == false);
    this->mp_stream_b->startRead();
    this->m_b_start_read = true;
    this->m_b_random = random_dist(random_engine);
} //}
void StreamRelay::__stop_a_to_b() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_a_start_read);
    this->mp_stream_a->stopRead();
    this->m_a_start_read = false;
    this->m_a_random = random_dist(random_engine);
} //}
void StreamRelay::__stop_b_to_a() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_b_start_read);
    this->mp_stream_b->stopRead();
    this->m_b_start_read = false;
    this->m_b_random = random_dist(random_engine);
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

