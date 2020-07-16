#pragma once

#include "stream.hpp"
#include "object_manager.h"

#include <uv.h>


class EBStreamUV: virtual public EBStreamAbstraction //{
{
    private:
        uv_tcp_t* mp_tcp;
        bool m_stream_read;
        static void __freeaddrinfo(struct addrinfo*);


    protected:
        void _write(ROBuf buf, WriteCallback cb, void* data) override;
        static void uv_write_callback(uv_write_t* req, int status);

        static void uv_connection_callback(uv_stream_t* stream, int status);
        static void uv_connect_callback(uv_connect_t* req, int status);
        static void uv_stream_read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
        static void uv_getaddrinfo_callback(uv_getaddrinfo_t* req, int status, struct addrinfo* res);

        static void getaddrinfo_callback(struct addrinfo* res, void(*__freeaddrinfoint)(struct addrinfo*), int status, void* data);


    public:
        bool bind(struct sockaddr* addr) override;
        bool listen() override;

        bool connect(struct sockaddr* addr, ConnectCallback cb, void* data) override;
        bool connect(uint32_t ipv4,              uint16_t port, ConnectCallback cb, void* data) override;
        bool connect(uint8_t  ipv6[16],          uint16_t port, ConnectCallback cb, void* data) override;
        bool connect(const std::string& domname, uint16_t port, ConnectCallback cb, void* data) override;
        bool connectINet6(const std::string& domname, uint16_t port, ConnectCallback cb, void* data) override;

        void stop_read() override;
        void start_read() override;
        bool in_read() override;

        void getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) override;
        void getaddrinfoipv4 (const char* hostname, GetAddrInfoIPv4Callback cb, void* data) override;
        void getaddrinfoipv6 (const char* hostname, GetAddrInfoIPv6Callback cb, void* data) override;

        void* newUnderlyStream() override;
        void  releaseUnderlyStream(void*) override;
        bool  accept(void* listen, void* stream) override;

        EBStreamUV(uv_tcp_t* tcp);
        ~EBStreamUV();

        void shutdown(ShutdownCallback cb, void* data) override;

        void* transfer() override;
        void  regain(void*) override;

        void  release() override;
        bool  hasStreamObject() override;

        std::string remote_addr() override;        // remote address
        uint16_t remote_port()    override;        // remote port
        std::string local_addr()  override;        // local address
        uint16_t local_port()     override;        // local port

        bool timeout(TimeoutCallback cb, void* data, int time) override;
}; //}


#include "StreamObject.h"
class EBStreamObjectUV: public EBStreamUV, public EBStreamObject //{
{
    public:
        inline EBStreamObjectUV(uv_tcp_t* connection, size_t max): 
            EBStreamUV(connection), EBStreamObject(max) {}
}; //}

