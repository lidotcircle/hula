#pragma once

#include "stream.hpp"

#include <uv.h>


class EBStreamUV: virtual public EBStreamAbstraction
{
    private:
        uv_tcp_t* mp_tcp;
        bool m_stream_read;


    protected:
        void _write(ROBuf buf, WriteCallback cb, void* data) override;
        static void uv_write_callback(uv_write_t* req, int status);

        bool bind(struct sockaddr* addr) override;
        bool listen() override;
        static void uv_connection_callback(uv_stream_t* stream, int status);

        bool connect(struct sockaddr* addr, ConnectCallback cb, void* data) override;
        static void uv_connect_callback(uv_connect_t* req, int status);

        void stop_read() override;
        void start_read() override;
        bool in_read() override;
        static void uv_stream_read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

        void getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) override;
        static void uv_getaddrinfo_callback(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
        void freeaddrinfo(struct addrinfo* addr) override;

        void* newUnderlyStream() override;
        void  releaseUnderlyStream(void*) override;
        bool  accept(void* listen, void* stream) override;

    public:
        EBStreamUV(uv_tcp_t* tcp);
        ~EBStreamUV();

        void* transfer() override;
        void  regain(void*) override;
};

