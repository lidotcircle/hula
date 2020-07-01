#pragma once

#include "stream.hpp"


class EBMemStream: virtual public EBStreamAbstraction
{
    private:
        bool  m_stream_read;
        bool  m_shutdown;
        ROBuf m_write_buffer;


    protected:
        void _write(ROBuf buf, WriteCallback cb, void* data) override;


    public:
        bool bind(struct sockaddr* addr) override;
        bool listen() override;

        bool connect(struct sockaddr* addr, ConnectCallback cb, void* data) override;

        void stop_read() override;
        void start_read() override;
        bool in_read() override;

        void getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) override;
        void getaddrinfoipv4 (const char* hostname, GetAddrInfoIPv4Callback cb, void* data) override;
        void getaddrinfoipv6 (const char* hostname, GetAddrInfoIPv6Callback cb, void* data) override;

        void* newUnderlyStream() override;
        void  releaseUnderlyStream(void*) override;
        bool  accept(void* listen, void* stream) override;

        EBMemStream();
        ~EBMemStream();

        void shutdown(ShutdownCallback cb, void* data) override;

        void* transfer() override;
        void  regain(void*) override;

        void  reply(ROBuf buf);
        ROBuf buffer();

        bool hasStreamObject() override;
};

