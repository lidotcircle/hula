#pragma once

#include "StreamProvider.h"
#include "object_manager.h"
#include "StreamObject.h"


class KProxyMultiplexerStreamProvider;
class KProxyMultiplexerService //{
{
    public:
        using _StreamId_ = StreamProvider::StreamId;
        virtual void CreateNewConnection(EBStreamObject* streamobj, _StreamId_ id, const std::string& addr, uint16_t port) = 0;
        virtual void CreateConnectionSuccess(_StreamId_) = 0;
        virtual void CreateConnectionFail   (_StreamId_, uint8_t reason) = 0;

        virtual void closeOtherEnd (_StreamId_) = 0;
}; //}


class KProxyMultiplexerStreamProvider: public virtual StreamProvider, virtual protected CallbackManager, public KProxyMultiplexerService //{
{
    private:
        class __KMStreamID: public __StreamID {
            private:
                friend class KProxyMultiplexerService;
                friend class KProxyMultiplexerStreamProvider;
                uint8_t m_id;
                EBStreamAbstraction* m_stream;

                RegisterReadCallback             m_read_callback       = nullptr;
                RegisterEndCallback              m_end_callback        = nullptr;
                RegisterErrorCallback            m_error_callback      = nullptr;
                RegisterCloseCallback            m_close_callback      = nullptr;
                RegisterShouldStartWriteCallback m_start_read_callback = nullptr;
                RegisterShouldStopWriteCallback  m_stop_read_callback  = nullptr;

                inline __KMStreamID(bool* lock, void freef(void*), uint8_t id, EBStreamAbstraction* stream):
                    __StreamID(lock, freef), m_id(id), m_stream(stream) {}
        };


    private:
        ROBuf m_remain;
        std::map<uint8_t, StreamId> m_allocator;
        struct __connect_state {ConnectCallback cb; void* data;};
        std::map<uint8_t, __connect_state> m_client_wait_connection;
        typename decltype(m_allocator)::key_type m_next_id;
        std::set<uint8_t> m_server_wait_connection;

        static void header_write_callback(ROBuf buf, int status, void* data);
        static void buffer_write_callback(ROBuf buf, int status, void* data);
        void write_header(ROBuf buf);
        void write_buffer(ROBuf buf, WriteCallback cb, void* data);
        void send_zero_packet(StreamId id, uint8_t opcode); // TODO
        using StreamProvider::finish;

        static void new_connection_write_callback  (ROBuf buf, int status, void* data);
        static void new_connection_timeout_callback(void* data);

        void dispatch_data(ROBuf buf);
        void create_new_connection(ROBuf req, uint8_t);


    private:
        StreamId createStreamID(bool* runlock, void (*freef)(void*), EBStreamAbstraction* stream) override;
        void lock_nextID_with(typename decltype(m_allocator)::key_type id);


    protected:
        void prm_read_callback(ROBuf buf) override;


    protected:
        bool    __full();
        uint8_t __getConnectionNumbers();

        void accept_connection(StreamId id);
        void reject_connection(StreamId id, uint8_t reason);


    public:
        KProxyMultiplexerStreamProvider();

        void connect(StreamId id, struct sockaddr*, ConnectCallback cb, void* data) override;
        void connect(StreamId id, uint32_t ipv4,    uint16_t port, ConnectCallback cb, void* data) override;
        void connect(StreamId id, uint8_t ipv6[16], uint16_t port, ConnectCallback cb, void* data) override;
        void connect(StreamId id, const std::string& addr, uint16_t port, ConnectCallback cb, void* data) override;
        void getaddrinfo(StreamId id, const std::string& addr, GetAddrInfoCallback cb, void* data) override;
        void getaddrinfoIPv4(StreamId id, const std::string& addr, GetAddrInfoIPv4Callback cb, void* data) override;
        void getaddrinfoIPv6(StreamId id, const std::string& addr, GetAddrInfoIPv6Callback cb, void* data) override;
        void write(StreamId, ROBuf buf, WriteCallback cb, void* data) override;
        void startRead(StreamId) override;
        void stopRead (StreamId) override;
        void closeOtherEnd (StreamId) override;
        void end(StreamId, EndCallback cb, void* data) override;
        void closeStream(StreamId) override;
        void timeout(TimeoutCallback cb, void* data, int time_ms) override;

        void registerReadCallback(StreamId, RegisterReadCallback) override;
        void registerErrorCallback(StreamId, RegisterErrorCallback) override;
        void registerCloseCallback(StreamId, RegisterErrorCallback) override;
        void registerEndCallback(StreamId, RegisterEndCallback) override;
        void registerShouldStartWriteCallback(StreamId, RegisterShouldStartWriteCallback) override;
        void registerShouldStopWriteCallback(StreamId, RegisterShouldStopWriteCallback) override;

        void changeOwner(StreamId, EBStreamAbstraction*) override;

        void CreateConnectionSuccess(StreamId) override;
        void CreateConnectionFail   (StreamId, uint8_t reason) override;
}; //}

