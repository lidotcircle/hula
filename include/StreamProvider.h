#pragma once

#include "stream.hpp"

#include <vector>
#include <assert.h>
#include <memory>
#include <map>

using namespace std;

class StreamProvider;
class __StreamID //{
{
    bool* m_run;
    void (*m_free)(void*);

    protected:
    friend class StreamProvider;
    inline __StreamID(bool* lock, void freef(void*) = nullptr): m_run(lock), m_free(freef) {}
    __StreamID() = delete;

    public:
    inline bool run() {assert(this->m_run != nullptr); return this->m_run;}
    inline virtual ~__StreamID() {assert(this->m_run != nullptr); if(this->m_free) this->m_free(this->m_run); else delete m_run; m_run = nullptr;}
}; //}


class StreamProvider //{
{
    private:
        std::map<EBStreamAbstraction*, bool*> m_run_lock;


    public:
        using StreamId                = shared_ptr<__StreamID>;
        using ConnectCallback         = void (*)(int status, void* data);
        using GetAddrInfoIPv4Callback = void (*)(vector<uint32_t>    addr, int status, void* data);
        using GetAddrInfoIPv6Callback = void (*)(vector<uint8_t[16]> addr, int status, void* data);
        using GetAddrInfoCallback     = void (*)(vector<uint32_t> ipv4_addr, vector<uint8_t[16]> ipv6_addr, int status, void* data);
        using WriteCallback           = void (*)(ROBuf buf, int status, void* data);
        using EndCallback             = WriteCallback;
        using TimeoutCallback         = void(*)(void* data);

        using RegisterReadCallback             = void (*)(EBStreamAbstraction*, ROBuf buf);
        using RegisterErrorCallback            = void (*)(EBStreamAbstraction*);
        using RegisterCloseCallback            = void (*)(EBStreamAbstraction*);
        using RegisterEndCallback              = void (*)(EBStreamAbstraction*);
        using RegisterShouldStartWriteCallback = void (*)(EBStreamAbstraction*);
        using RegisterShouldStopWriteCallback  = void (*)(EBStreamAbstraction*);


    protected:
        virtual StreamId createStreamID(bool* runlock, void (*freef)(void*), EBStreamAbstraction* stream) = 0;

        /** primitive */
        virtual void prm_write(ROBuf, WriteCallback cb, void* data) = 0;
        virtual void prm_timeout(TimeoutCallback cb, void* data, int time_ms) = 0;

        virtual void prm_read_callback(ROBuf buf) = 0;

        /* call this function when underly primitive error. 
         * ex. initialize error, write error, read error, ... 
         * intent to clean resources relate to services */
        virtual void prm_error_handle() = 0;


    public:
        virtual StreamId init(EBStreamAbstraction* stream);
        virtual void finish(EBStreamAbstraction* stream);

        /** services */
        virtual void connect(StreamId id, struct sockaddr*, ConnectCallback cb, void* data) = 0;
        virtual void connect(StreamId id, uint32_t ipv4,    uint16_t port, ConnectCallback cb, void* data) = 0;
        virtual void connect(StreamId id, uint8_t ipv6[16], uint16_t port, ConnectCallback cb, void* data) = 0;
        virtual void connect(StreamId id, const std::string& addr, uint16_t port, ConnectCallback cb, void* data) = 0;
        virtual void getaddrinfo(StreamId id, const std::string& addr, GetAddrInfoCallback cb, void* data) = 0;
        virtual void getaddrinfoIPv4(StreamId id, const std::string& addr, GetAddrInfoIPv4Callback cb, void* data) = 0;
        virtual void getaddrinfoIPv6(StreamId id, const std::string& addr, GetAddrInfoIPv6Callback cb, void* data) = 0;
        virtual void write(StreamId, ROBuf buf, WriteCallback cb, void* data) = 0;
        virtual void startRead(StreamId) = 0;
        virtual void stopRead (StreamId) = 0;
        virtual void end(StreamId, EndCallback cb, void* data) = 0;
        virtual void closeStream(StreamId) = 0;
        virtual void timeout(TimeoutCallback cb, void* data, int time_ms) = 0;

        virtual void registerReadCallback(StreamId, RegisterReadCallback) = 0;
        virtual void registerErrorCallback(StreamId, RegisterErrorCallback) = 0;
        virtual void registerCloseCallback(StreamId, RegisterErrorCallback) = 0;
        virtual void registerEndCallback(StreamId, RegisterEndCallback) = 0;
        virtual void registerShouldStartWriteCallback(StreamId, RegisterShouldStartWriteCallback) = 0;
        virtual void registerShouldStopWriteCallback(StreamId, RegisterShouldStopWriteCallback) = 0;

        virtual ~StreamProvider();
}; //}

