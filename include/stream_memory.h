#pragma once

#include "stream.hpp"


class EBMemStream: virtual public EBStreamAbstraction
{
    private:
        bool  m_stream_read;
        ROBuf m_write_buffer;


    protected:
        void _write(ROBuf buf, WriteCallback cb, void* data) override;

        bool bind(struct sockaddr* addr) override;
        bool listen() override;

        bool connect(struct sockaddr* addr, ConnectCallback cb, void* data) override;

        void stop_read() override;
        void start_read() override;
        bool in_read() override;

        void getaddrinfo (const char* hostname, GetAddrInfoCallback cb, void* data) override;

        void* newUnderlyStream() override;
        void  releaseUnderlyStream(void*) override;
        bool  accept(void* listen, void* stream) override;

    public:
        EBMemStream();
        ~EBMemStream();

        void* transfer() override;
        void  regain(void*) override;

        void  reply(ROBuf buf);
        ROBuf buffer();
};

