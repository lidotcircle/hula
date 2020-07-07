#pragma once

#include "events.h"
#include "robuf.h"
#include "config.h"
#include "object_manager.h"

#include <assert.h>
#define CALL_PURE_VIRTUAL_FUNCTION() assert(false && "call pure virtual function")

/* forward declaration */
struct addrinfo;
struct sockaddr;

class EBStreamAbstraction: virtual public EventEmitter //{
{
    public:
        /** #status < 0 means error */
        using WriteCallback           = void (*)(ROBuf buf, int status, void* data);
        using ReadCallback            = void(*)(ROBuf buf, int status);
        using GetAddrInfoCallback     = void(*)(struct addrinfo* addr, void(*free)(struct addrinfo*), int status, void* data);
        using GetAddrInfoIPv4Callback = void(*)(uint32_t ipv4, int status, void* data);
        using GetAddrInfoIPv6Callback = void(*)(uint8_t  ipv6[16], int status, void* data);
        using ConnectCallback         = void(*)(int status, void* data);
        using ShutdownCallback        = void(*)(int status, void* data);
        using TimeoutCallback         = void(*)(void* data);


    protected:
        enum CONNECTION_STATE { 
            UNINITIAL = 0, INITIAL, CONNECTING,
            CONNECT, GIVEUP, CLOSED,
            LISTENNING
        };
        CONNECTION_STATE m_state;

        virtual void _write(ROBuf buf, WriteCallback cb, void* data) = 0;

        inline virtual void read_callback(ROBuf buf, int status) {CALL_PURE_VIRTUAL_FUNCTION();};
        inline virtual void end_signal() {CALL_PURE_VIRTUAL_FUNCTION();};
        inline virtual void on_connection(void* connection) {CALL_PURE_VIRTUAL_FUNCTION();};


    public:
        virtual bool bind(struct sockaddr* addr) = 0;
        virtual bool listen() = 0;

        virtual bool connect(struct sockaddr* addr, ConnectCallback cb, void* data) = 0;
        /** local machine byte order */
        virtual bool connect(uint32_t ipv4,              uint16_t port, ConnectCallback cb, void* data) = 0;
        virtual bool connect(uint8_t  ipv6[16],          uint16_t port, ConnectCallback cb, void* data) = 0;
        virtual bool connect(const std::string& domname, uint16_t port, ConnectCallback cb, void* data) = 0;
        virtual bool connectINet6(const std::string& domname, uint16_t port, ConnectCallback cb, void* data) = 0;

        virtual void stop_read() = 0;
        virtual void start_read() = 0;
        virtual bool in_read() = 0;

        virtual void getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) = 0;
        virtual void getaddrinfoipv4 (const char* hostname, GetAddrInfoIPv4Callback cb, void* data) = 0;
        virtual void getaddrinfoipv6 (const char* hostname, GetAddrInfoIPv6Callback cb, void* data) = 0;

        virtual void* newUnderlyStream() = 0;
        virtual void  releaseUnderlyStream(void*) = 0;
        virtual bool  accept(void* listen, void* stream) = 0;

        inline virtual ~EBStreamAbstraction() {};

        virtual void shutdown(ShutdownCallback cb, void* data) = 0;

        virtual void* transfer() = 0;
        virtual void  regain(void*) = 0;

        virtual void  release() = 0;
        virtual bool  hasStreamObject() = 0;

        virtual void timeout(TimeoutCallback cb, void* data, int time_ms) = 0;
}; //}

/**
 * @event drain
 * @event data
 * @event connect
 * @event end
 * @event error
 * @event close
 */
class EBStreamObject: virtual protected EBStreamAbstraction, protected CallbackManager, virtual public EventEmitter //{
{
    public:
        using WriteCallback       = EBStreamAbstraction::WriteCallback;
        using ConnectCallback     = EBStreamAbstraction::ConnectCallback;
        using GetAddrInfoCallback = EBStreamAbstraction::GetAddrInfoCallback;
        struct DataArgs: public EventArgs::Base {
            ROBuf _buf;
            inline DataArgs(ROBuf buf): _buf(buf) {}
        };
        struct ErrorArgs: public EventArgs::Base {
            std::string _msg;
            inline ErrorArgs(const std::string& err): _msg(err) {}
        };
        struct DrainArgs: public EventArgs::Base {};
        struct CloseArgs: public EventArgs::Base {};
        struct EndArgs: public EventArgs::Base {};
        struct ConnectArgs: public EventArgs::Base {};


    private:
        size_t m_max_write_buffer_size;
        size_t m_writed_size;

        bool m_end;
        bool m_closed;

        void* m_store_ptr;

        static void write_callback(ROBuf, int status, void* data);
        static void connect_callback(int status, void* data);

    protected:
        void read_callback(ROBuf buf, int status) override;
        void end_signal() override;


    public:
        EBStreamObject(size_t max_write_buffer_size);

        int  write(ROBuf);
        bool connectTo(struct sockaddr*);
        bool connectTo(uint32_t ipv4, uint16_t port);
        bool connectTo(uint8_t ipv6[16], uint16_t port);
        bool connectTo(const std::string& addr, uint16_t port);
        void getDNS(const std::string& addr, GetAddrInfoCallback cb, void* data);
        void startRead();
        void stopRead();
        void end();
        void close();

        void  storePtr(void* ptr);
        void* fetchPtr();
}; //}

