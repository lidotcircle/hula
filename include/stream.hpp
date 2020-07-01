#pragma once

#include "events.h"
#include "robuf.h"
#include "config.h"

#include <assert.h>
#define CALL_PURE_VIRTUAL_FUNCTION() assert(false && "call pure virtual function")

/* forward declaration */
struct addrinfo;
struct sockaddr;

class EBStreamAbstraction: virtual public EventEmitter //{
{
    public:
        /** #status < 0 means error */
        using WriteCallback = void (*)(ROBuf buf, int status, void* data);
        using ReadCallback = void(*)(ROBuf buf, int status);
        using GetAddrInfoCallback = void(*)(struct addrinfo* addr, void(*free)(struct addrinfo*), int status, void* data);
        using ConnectCallback = void(*)(int status, void* data);


    protected:
        enum CONNECTION_STATE { 
            UNINITIAL = 0, INITIAL, CONNECTING,
            CONNECT, GIVEUP, CLOSED,
            LISTENNING
        };
        CONNECTION_STATE m_state;

        virtual void _write(ROBuf buf, WriteCallback cb, void* data) = 0;

        inline virtual void read_callback(ROBuf buf, int status) {CALL_PURE_VIRTUAL_FUNCTION();};
        inline virtual void on_connection(void* connection) {CALL_PURE_VIRTUAL_FUNCTION();};


    public:
        virtual bool bind(struct sockaddr* addr) = 0;
        virtual bool listen() = 0;

        virtual bool connect(struct sockaddr* addr, ConnectCallback cb, void* data) = 0;

        virtual void stop_read() = 0;
        virtual void start_read() = 0;
        virtual bool in_read() = 0;

        virtual void getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) = 0;

        virtual void* newUnderlyStream() = 0;
        virtual void  releaseUnderlyStream(void*) = 0;
        virtual bool  accept(void* listen, void* stream) = 0;

        inline virtual ~EBStreamAbstraction() {};

        virtual void* transfer() = 0;
        virtual void  regain(void*) = 0;
}; //}

