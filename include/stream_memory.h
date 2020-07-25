#pragma once

#include "stream.h"
#include "robuf.h"

#include <sstream>

class EBMemStream: virtual public EBStreamAbstraction
{
    private:
        bool  m_stream_read;
        bool  m_shutdown;
        ROBuf m_write_buffer;
        class __UnderlyingStreamMem: public __UnderlyingStream {
            public:
            inline __UnderlyingStreamMem(StreamType type): __UnderlyingStream(type) {}
            inline bool is_null() override {return false;}
        };


    protected:
        void _write(ROBuf buf, WriteCallback cb, void* data) override;

        std::stringstream m_buffer;
        std::stringstream m_in_transform;
        using CoutType = std::basic_ostream<char, std::char_traits<char>>;
        using StdEndl  = CoutType& (*)(CoutType&);
        using Manipu   = EBMemStream& (*)(EBMemStream&);


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
        void releaseUnderlyStream(UNST) override;
        bool accept(UNST stream) override;

        template<typename T>
        EBMemStream& operator<<(const T& value) //{
        {
            this->m_in_transform << value;
            std::string result(std::istreambuf_iterator<char>(this->m_in_transform), {});
            if(result.size() > 0) {
                ROBuf buf((char*)result.c_str(), result.size(), 0);
                this->read_callback(buf, 0);
            }
            return (*this);
        } //}
        inline EBMemStream& operator<<(StdEndl endl) //{
        {
            (*this) << EBMemStream::endl;
            endl(this->m_buffer);
            return *this;
        } //}
        inline EBMemStream& operator<<(Manipu manip) //{
        {
            return manip(*this);
        } //}
        inline static EBMemStream& endl(EBMemStream& stream) //{
        {
            stream << '\n';
            return stream;
        } //}
        inline std::istream& istream() {return this->m_buffer;}

        EBMemStream();
        ~EBMemStream();

        void shutdown(ShutdownCallback cb, void* data) override;

        UNST transfer() override;
        void regain(UNST) override;

        void  reply(ROBuf buf);
        ROBuf buffer();

        bool hasStreamObject() override;
        void release() override;

        StreamType getType() override;

        bool timeout(TimeoutCallback cb, void* data, int time_ms) override;
};

