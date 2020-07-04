#include "../include/stream.hpp"
#include "../include/utils.h"


void EBStreamObject::read_callback(ROBuf buf, int status) //{
{
    if(status == 0) {
        this->emit("data", new DataArgs(buf));
    } else {
        this->emit("error", new ErrorArgs("read error"));
    }
} //}
void EBStreamObject::end_signal() //{
{
    this->emit("end", new EndArgs());
} //}

EBStreamObject::EBStreamObject(size_t m) //{
{
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
        _this->emit("drain", new DrainArgs());
    }
    return;
} //}

struct EBStreamObject$connectWith_sockaddr$connect: public CallbackPointer {
    EBStreamObject* _this;
    inline EBStreamObject$connectWith_sockaddr$connect(EBStreamObject* _this): _this(_this) {}
};
int EBStreamObject::connectWith_sockaddr(sockaddr* addr) //{
{
    assert(this->m_end == false && this->m_closed == false);
    auto ptr = new EBStreamObject$connectWith_sockaddr$connect(this);
    this->add_callback(ptr);
    return this->connect(addr, connect_callback, ptr);
} //}
int EBStreamObject::connectWith_address(const std::string& addr, uint16_t port) //{
{
    assert(this->m_end == false && this->m_closed == false);
    auto ptr = new EBStreamObject$connectWith_sockaddr$connect(this);
    this->add_callback(ptr);
    return this->connect(addr, port, connect_callback, ptr);
} //}
/** [static] */
void EBStreamObject::connect_callback(int status, void* data) //{
{
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
    assert(this->m_closed == false);
    this->getaddrinfo(addr.c_str(), cb, data);
} //}

void EBStreamObject::startRead() {assert(this->m_end == false && this->m_closed == false); this->start_read();}
void EBStreamObject::stopRead()  {assert(this->m_end == false && this->m_closed == false); this->stop_read();}
static void dummy_end_callback(int, void*) {}
void EBStreamObject::end()       //{
{
    assert(this->m_end == false && this->m_closed == false); 
    this->m_end = true; 
    this->shutdown(dummy_end_callback, nullptr);
} //}

void EBStreamObject::close() //{
{
    assert(this->m_closed == false);
    this->m_closed = true;
    this->emit("close", new CloseArgs());
} //}

void  EBStreamObject::storePtr(void* ptr) {this->m_store_ptr = ptr;}
void* EBStreamObject::fetchPtr() {return this->m_store_ptr;}

