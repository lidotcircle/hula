#pragma once

#include "stream.hpp"

#include <vector>
#include <assert.h>
#include <memory>

using namespace std;

class StreamProvider;
class __StreamID //{
{
    uint8_t m_id; 
    EBStreamAbstraction* m_stream;
    bool* m_run;
    void (*m_free)(void*);

    protected:
    friend class StreamProvider;
    inline __StreamID(uint8_t id, EBStreamAbstraction* stream, bool* lock, void freef(void*) = nullptr): 
        m_id(id), m_stream(stream), m_run(lock), m_free(freef) {}
    inline __StreamID(): m_id(0), m_stream(nullptr), m_run(nullptr) {}

    public:
    inline bool run()    {assert(this->m_run != nullptr); return this->m_run;}
    inline ~__StreamID() {assert(this->m_run != nullptr); if(this->m_free) this->m_free(this->m_run); else delete m_run; m_run = nullptr;}
}; //}


class StreamProvider //{
{
    public:
        using StreamId                = shared_ptr<__StreamID>;
        using ConnectCallback         = void (*)(int status, void* data);
        using GetAddrInfoIPv4Callback = void (*)(vector<uint32_t>    addr, int status, void* data);
        using GetAddrInfoIPv6Callback = void (*)(vector<uint8_t[16]> addr, int status, void* data);
        using GetAddrInfoCallback     = void (*)(vector<uint32_t> ipv4_addr, vector<uint8_t> ipv6_addr, int status, void* data);
        using WriteCallback           = void (*)(ROBuf buf, int status, void* data);
        using EndCallback             = void (*)(int status, void* data);
        using TimeoutCallback         = void(*)(void* data);


    public:
        virtual StreamId init(EBStreamAbstraction* stream);
        virtual void connect(struct sockaddr*, uint16_t port, ConnectCallback cb, void* data) = 0;
        virtual void connect(uint32_t ipv4,    uint16_t port, ConnectCallback cb, void* data) = 0;
        virtual void connect(uint8_t ipv6[16], uint16_t port, ConnectCallback cb, void* data) = 0;
        virtual void connect(const std::string& addr, uint16_t port, ConnectCallback cb, void* data) = 0;
        virtual void getaddrinfo(const std::string& addr, GetAddrInfoCallback cb, void* data) = 0;
        virtual void getaddrinfoIPv4(const std::string& addr, GetAddrInfoIPv4Callback cb, void* data) = 0;
        virtual void getaddrinfoIPv6(const std::string& addr, GetAddrInfoIPv6Callback cb, void* data) = 0;
        virtual void write(StreamId, ROBuf buf, WriteCallback cb, void* data) = 0;
        virtual void startRead(StreamId) = 0;
        virtual void stopRead (StreamId) = 0;
        virtual void end(StreamId, EndCallback cb, void* data) = 0;
        virtual void closeStream(StreamId) = 0;
        virtual void timeout(TimeoutCallback cb, void* data, int time_ms) = 0;

        virtual inline ~StreamProvider() {}
}; //}

