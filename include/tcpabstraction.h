#pragma once 

#include "robuf.h"
#include "events.h"
#include "libuv_utils.h"

#include <uv.h>

#include <assert.h>

#include <set>
#include <sstream>
#include <iostream>

template<typename O>
class TCPAbstractConnection //{
{
    public:
        /** #status<0 means error */
        using WriteCallback = void (*)(O* obj, ROBuf buf, int status, void* data);
        using ReadCallback = void(*)(O* obj, ROBuf buf, int status);

    protected:
        virtual void _write(ROBuf buf, WriteCallback cb, void* data) = 0;

        virtual void read_callback(ROBuf buf, int status) = 0;

        virtual void stop_read() = 0;
        virtual void start_read() = 0;

    public:
        inline virtual ~TCPAbstractConnection() {};
}; //}

using TCPAbstractConnectionEventBase = TCPAbstractConnection<EventEmitter>;
inline static void uv_malloc_cb(uv_handle_t*, size_t suggested_size, uv_buf_t* buf) //{
{
    buf->base = (char*)malloc(suggested_size);
    buf->len  = suggested_size;
} //}
class UVTCPAbstractConnection: virtual public TCPAbstractConnectionEventBase, virtual public EventEmitter //{
{
    public:
        using WriteCallback = typename TCPAbstractConnectionEventBase::WriteCallback;

    protected:
        struct __write_state {
            UVTCPAbstractConnection* _this; 
            ROBuf* _holder; 
            uv_buf_t* _uv_buf; 
            bool should_run = true;
            WriteCallback _cb;
            void* _data;
            __write_state(UVTCPAbstractConnection* _this, ROBuf* _holder, uv_buf_t* _uv_buf, WriteCallback cb, void* data):
                _this(_this), _holder(_holder), _uv_buf(_uv_buf), _cb(cb), _data(data) {}
        };
        std::set<__write_state*> m_write_callback_list;
        void insert_callback(__write_state*);
        void remove_callback(__write_state*);

        uv_tcp_t* m_connection;
        bool m_start_read;

        static void uv_read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
        static void uv_write_callback(uv_write_t* req, int status);
        void _write(ROBuf buf, WriteCallback cb, void* data);

        void stop_read();
        void start_read();

    public:
        UVTCPAbstractConnection(uv_tcp_t* connection);

        void getConnection(uv_tcp_t* connection);
        uv_tcp_t* transfer();

        ~UVTCPAbstractConnection();
}; //}

class MemoryTCPAbstractConnection: virtual public TCPAbstractConnectionEventBase, virtual public EventEmitter //{
{
    public:
        using WriteCallback = typename TCPAbstractConnectionEventBase::WriteCallback;

    protected:
        std::stringstream m_buffer;
        std::stringstream m_in_transform;

        bool m_start_read;

        void _write(ROBuf buf, WriteCallback cb, void* data);

        void stop_read();
        void start_read();

        using CoutType = std::basic_ostream<char, std::char_traits<char>>;
        using StdEndl  = CoutType& (*)(CoutType&);
        using Manipu   = MemoryTCPAbstractConnection& (*)(MemoryTCPAbstractConnection&);

    public:
        MemoryTCPAbstractConnection();
        template<typename T>
        MemoryTCPAbstractConnection& operator<<(const T& value) //{
        {
            this->m_in_transform << value;
            std::string result(std::istreambuf_iterator<char>(this->m_in_transform), {});
            if(result.size() > 0) {
                ROBuf buf((char*)result.c_str(), result.size(), 0);
                this->read_callback(buf, 0);
            }
            return (*this);
        } //}
        inline MemoryTCPAbstractConnection& operator<<(StdEndl endl) //{
        {
            (*this) << MemoryTCPAbstractConnection::endl;
            endl(this->m_buffer);
            return *this;
        } //}
        inline MemoryTCPAbstractConnection& operator<<(Manipu manip) //{
        {
            return manip(*this);
        } //}
        inline static MemoryTCPAbstractConnection& endl(MemoryTCPAbstractConnection& stream) //{
        {
            stream << '\n';
            return stream;
        } //}
        inline std::istream& istream() {return this->m_buffer;}
        ~MemoryTCPAbstractConnection();
}; //}

