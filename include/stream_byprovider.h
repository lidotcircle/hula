#pragma once

#include "stream.hpp"
#include "StreamProvider.h"


class EBStreamByProvider: public virtual EBStreamAbstraction //{
{
    private:
        StreamProvider* mp_provider;
        bool m_stream_read;
        static void __freeaddrinfo(struct addrinfo*);


    protected:
        void _write(ROBuf buf, WriteCallback cb, void* data) override;


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

        EBStreamByProvider(StreamProvider* tcp);
        ~EBStreamByProvider();

        void shutdown(ShutdownCallback cb, void* data) override;

        void* transfer() override;
        void  regain(void*) override;

        void  release() override;
        bool  hasStreamObject() override;

        void timeout(TimeoutCallback cb, void* data, int time) override;

}; //}

