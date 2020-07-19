#pragma once

#include "stream.h"
#include "StreamObject.h"
#include "StreamProvider.h"


class EBStreamByProvider: public virtual EBStreamAbstraction //{
{
    private:
        struct __virtualbase {inline virtual ~__virtualbase() {}};
        struct __info_type: public __virtualbase {
            StreamProvider* mp_provider = nullptr;
            StreamProvider::StreamId m_id;
            bool m_send_end = false;
        }* m_info;
        bool m_stream_read;

        class __UnderlyingStreamProvider: public __UnderlyingStream {
            __info_type* msg;
            public:
            inline __UnderlyingStreamProvider(StreamType type, __info_type* msg): __UnderlyingStream(type), msg(msg) {}
            inline __info_type* getStream() {return msg;}
        };

        std::string m_stat_remote_address;
        std::string m_stat_local_address;
        uint16_t    m_stat_remote_port;
        uint16_t    m_stat_local_port;

        static void __freeaddrinfo(struct addrinfo*);

        static void write_callback(ROBuf buf, int status, void* data);
        static void connect_callback(int status, void* data);
        static void shutdown_callback(ROBuf buf, int status, void* data);

        static void getaddrinfo_callback(std::vector<uint32_t> ipv4, std::vector<uint8_t[16]> ipv6, int status, void* data);
        static void getaddrinfoipv4_callback(std::vector<uint32_t> ipv4s, int status, void* data);
        static void getaddrinfoipv6_callback(std::vector<uint8_t[16]> ipv6s, int status, void* data);

        void register_callback();
        static void r_read_callback(EBStreamAbstraction* obj, ROBuf);
        static void r_error_callback(EBStreamAbstraction* obj);
        static void r_end_callback(EBStreamAbstraction* obj);
        static void r_shouldstartwrite_callback(EBStreamAbstraction* obj);
        static void r_shouldstopwrite_callback(EBStreamAbstraction* obj);


    protected:
        void _write(ROBuf buf, WriteCallback cb, void* data) override;
        StreamProvider* getProvider();


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

        UNST newUnderlyStream() override;
        void  releaseUnderlyStream(UNST) override;
        bool  accept(UNST listen, UNST stream) override;

        EBStreamByProvider(StreamProvider* tcp);
        ~EBStreamByProvider();

        void shutdown(ShutdownCallback cb, void* data) override;

        UNST transfer() override;
        void regain(UNST) override;

        void  release() override;
        bool  hasStreamObject() override;

        bool timeout(TimeoutCallback cb, void* data, int time) override;
}; //}


class EBStreamObjectKProxyMultiplexerProvider: public EBStreamByProvider, public EBStreamObject //{
{
    public:
        inline EBStreamObjectKProxyMultiplexerProvider(StreamProvider* connection, size_t max): 
            EBStreamByProvider(connection), EBStreamObject(max) {}

        StreamType getType() override;
        EBStreamObject* NewStreamObject() override;
}; //}

