#pragma once

#include "events.h"
#include "robuf.h"

/* forward declaration */
struct addrinfo;
struct sockaddr;

class EBStreamAbstraction: virtual public EventEmitter //{
{
    public:
        /** #status < 0 means error */
        using WriteCallback = void (*)(EventEmitter* obj, ROBuf buf, int status, void* data);
        using ReadCallback = void(*)(EventEmitter* obj, ROBuf buf, int status);
        using GetAddrInfoCallback = void(*)(EventEmitter* obj, struct addrinfo* addr, int status, void* data);
        using ConnectCallback = void(*)(EventEmitter* obj, int status, void* data);


    protected:
        virtual void _write(ROBuf buf, WriteCallback cb, void* data) = 0;

        virtual void read_callback(ROBuf buf, int status) = 0;
        virtual void on_connection(void* connection) = 0;

        virtual bool bind(struct sockaddr* addr) = 0;
        virtual bool listen() = 0;

        virtual bool connect(struct sockaddr* addr, ConnectCallback cb, void* data) = 0;

        virtual void stop_read() = 0;
        virtual void start_read() = 0;
        virtual bool in_read() = 0;

        enum CONNECTION_STATE { 
            UNINITIAL = 0, INITIAL, CONNECTING,
            CONNECT, GIVEUP, CLOSED,
            LISTENNING
        };
        CONNECTION_STATE m_state;

        virtual void getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) = 0;
        virtual void freeaddrinfo(struct addrinfo* addr) = 0;

        virtual void* newUnderlyStream() = 0;
        virtual void  releaseUnderlyStream(void*) = 0;
        virtual bool  accept(void* listen, void* stream) = 0;

    public:
        inline virtual ~EBStreamAbstraction() {};

        virtual void* transfer() = 0;
        virtual void  regain(void*) = 0;
}; //}

