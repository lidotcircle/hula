#include "../include/stream.hpp"
#include "../include/utils.h"

#include "../include/logger.h"
#include "../include/config.h"


void EBStreamObject::read_callback(ROBuf buf, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    if(status == 0) {
        this->emit("data", new DataArgs(buf));
    } else {
        this->emit("error", new ErrorArgs("read error"));
    }
} //}
void EBStreamObject::end_signal() //{
{
    __logger->debug("call %s", FUNCNAME);
    this->emit("end", new EndArgs());
} //}

EBStreamObject::EBStreamObject(size_t m) //{
{
    __logger->debug("call %s", FUNCNAME);
    this->m_max_write_buffer_size = m;
    this->m_writed_size = 0;
    this->m_closed = false;
    this->m_end = false;
    this->m_store_ptr = nullptr;
} //}

struct EBStreamObject$write$_write: public CallbackPointer {
    EBStreamObject* _this;
    inline EBStreamObject$write$_write(EBStreamObject* _this): _this(_this) {}
};
int EBStreamObject::write(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false);
    this->m_writed_size += buf.size();
    auto ptr = new EBStreamObject$write$_write(this);
    this->add_callback(ptr);
    this->_write(buf, write_callback, ptr);
    return (this->m_writed_size > this->m_max_write_buffer_size) ? -1 : 0;
} //}
/** [static] */
void EBStreamObject::write_callback(ROBuf buf, int status, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    EBStreamObject$write$_write* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);
    auto _this = msg->_this;
    auto run   = msg->CanRun();
    delete msg;
    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0) {
        _this->emit("error", new ErrorArgs("write error"));
        return;
    }

    _this->m_writed_size -= buf.size();
    if(_this->m_writed_size <= _this->m_max_write_buffer_size &&
       _this->m_writed_size + buf.size() > _this->m_max_write_buffer_size) {
        /*
        int n = _this->numberOfListener("drain");
        __logger->warn("write_callback() DRAIN with %d listener", n);
        std::cout << "object: " << _this << std::endl;
        for(auto& x: _this->listeners())
            std::cout << "    listener of " << x.first << ": " << x.second << std::endl;
        */
        _this->emit("drain", new DrainArgs());
    }
    return;
} //}

struct EBStreamObject$connectWith_sockaddr$connect: public CallbackPointer {
    EBStreamObject* _this;
    inline EBStreamObject$connectWith_sockaddr$connect(EBStreamObject* _this): _this(_this) {}
};
bool EBStreamObject::connectTo(struct sockaddr* addr) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false);
    auto ptr = new EBStreamObject$connectWith_sockaddr$connect(this);
    this->add_callback(ptr);
    return this->connect(addr, connect_callback, ptr);
} //}
bool EBStreamObject::connectTo(const std::string& addr, uint16_t port) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false);
    auto ptr = new EBStreamObject$connectWith_sockaddr$connect(this);
    this->add_callback(ptr);
    return this->connect(addr, port, connect_callback, ptr);
} //}
bool EBStreamObject::connectTo(uint32_t ipv4, uint16_t port) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false);
    auto ptr = new EBStreamObject$connectWith_sockaddr$connect(this);
    this->add_callback(ptr);
    return this->connect(ipv4, port, connect_callback, ptr);
} //}
bool EBStreamObject::connectTo(uint8_t ipv6[16], uint16_t port) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false);
    auto ptr = new EBStreamObject$connectWith_sockaddr$connect(this);
    this->add_callback(ptr);
    return this->connect(ipv6, port, connect_callback, ptr);
} //}
/** [static] */
void EBStreamObject::connect_callback(int status, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
   EBStreamObject$connectWith_sockaddr$connect* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);
    auto _this = msg->_this;
    auto run   = msg->CanRun();
    delete msg;

    if(!run) return; // FIXME invalid read
    _this->remove_callback(msg);

    if(status < 0) {
        _this->emit("error", new ErrorArgs("connect error"));
        return;
    }

    _this->emit("connect", new ConnectArgs());
} //}

void EBStreamObject::getDNS(const std::string& addr, GetAddrInfoCallback cb, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_closed == false);
    this->getaddrinfo(addr.c_str(), cb, data);
} //}

void EBStreamObject::startRead() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false); 
    this->start_read();
} //}
void EBStreamObject::stopRead()  //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false); 
    this->stop_read();
} //}
static void dummy_end_callback(int, void*) {}
void EBStreamObject::end()       //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_end == false && this->m_closed == false); 
    this->m_end = true; 
    this->shutdown(dummy_end_callback, nullptr);
} //}

void EBStreamObject::close() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_closed == false);
    this->m_closed = true;
    this->emit("close", new CloseArgs());
} //}

void  EBStreamObject::storePtr(void* ptr) {this->m_store_ptr = ptr;}
void* EBStreamObject::fetchPtr() {return this->m_store_ptr;}

