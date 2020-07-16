#pragma once

#include "stream.hpp"


/**
 * @event drain
 * @event data
 * @event connect
 * @event end
 * @event error
 * @event close
 *
 * @event shouldStartRead
 * @event shouldStopRead
 */
class EBStreamObject: virtual protected EBStreamAbstraction, virtual protected CallbackManager, virtual public EventEmitter //{
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

        struct ShouldStartWriteArgs: public EventArgs::Base {};
        struct ShouldStopWriteArgs:  public EventArgs::Base {};


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

        void should_start_write() override;
        void should_stop_write () override;


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
        
        void SetTimeout(TimeoutCallback cb, void* data, int time_ms);

        void  storePtr(void* ptr);
        void* fetchPtr();

        virtual ~EBStreamObject();
}; //}

