#include "../include/stream_memory.h"

#include <iostream>

#include <assert.h>
#include <stdlib.h>


void EBMemStream::_write(ROBuf buf, WriteCallback cb, void* data) //{
{
    if(this->m_state == CONNECTION_STATE::UNINITIAL ||
       this->m_state == CONNECTION_STATE::CLOSED ||
       this->m_state == CONNECTION_STATE::GIVEUP ||
       this->m_state == CONNECTION_STATE::LISTENNING) {
        assert(false && "bad function call");
    }
    std::cout << "write: " << buf << std::endl;
    this->m_write_buffer = this->m_write_buffer + buf;
    cb(this, buf, 0, data);
    return;
} //}

bool EBMemStream::bind(struct sockaddr* addr) //{
{
    return true;
} //}
bool EBMemStream::listen() //{
{
    assert(this->m_state == CONNECTION_STATE::INITIAL);
    this->m_state = CONNECTION_STATE::LISTENNING;
    return true;
} //}

bool EBMemStream::connect(struct sockaddr* addr, ConnectCallback cb, void* data) //{
{
    assert(this->m_state == CONNECTION_STATE::INITIAL);
    this->m_state = CONNECTION_STATE::CONNECT;
    cb(this, 0, data);
    return true;
} //}

void EBMemStream::stop_read() //{
{
    assert(this->m_stream_read == true);
    this->m_stream_read = false;
} //}
void EBMemStream::start_read() //{
{
    assert(this->m_stream_read == false);
    this->m_stream_read = true;
} //}
bool EBMemStream::in_read() //{
{
    return this->m_stream_read;
} //}

void EBMemStream::getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) //{
{
    cb(this, nullptr, 0, data);
} //}
void EBMemStream::freeaddrinfo(struct addrinfo* addr) //{
{
    free(addr);
} //}

void* EBMemStream::newUnderlyStream() //{
{
    return nullptr;
} //}
void  EBMemStream::releaseUnderlyStream(void*) //{
{
    return;
} //}
bool  EBMemStream::accept(void* listen, void* stream) //{
{
    assert(false && "unimplemented");
    return true;
} //}

EBMemStream::EBMemStream() {
    this->m_state = CONNECTION_STATE::INITIAL;
    this->m_stream_read = false;
}
EBMemStream::~EBMemStream() {}

void* EBMemStream::transfer()      {
    assert(this->m_state != CONNECTION_STATE::GIVEUP);
    this->m_state = CONNECTION_STATE::GIVEUP;
    return nullptr;
}
void  EBMemStream::regain(void*)   {
    assert(this->m_state == CONNECTION_STATE::UNINITIAL ||
           this->m_state == CONNECTION_STATE::GIVEUP);
    this->m_state = CONNECTION_STATE::CONNECT;
    return;
}

void  EBMemStream::reply(ROBuf buf) {this->read_callback(buf, 0);}
ROBuf EBMemStream::buffer()         {return this->m_write_buffer;}

