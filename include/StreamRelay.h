#pragma once

#include "stream.hpp"

/** @class relay traffic between two StreamObject */
class StreamRelay //{
{
    private:
        EBStreamObject *mp_stream_a, *mp_stream_b;
        bool m_a_start_read, m_b_start_read;
        bool m_a_end, m_b_end;

        EventEmitter::EventListener m_a_drain_listener_reg, m_b_drain_listener_reg;

        void register_b_listener();
        void register_a_listener();
        static void a_data_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);
        static void b_data_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);

        static void a_drain_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);
        static void b_drain_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);

        static void a_end_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);
        static void b_end_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);

        static void a_error_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);
        static void b_error_listener(EventEmitter* obj, const std::string& event, EventArgs::Base* args);

        void __relay_a_to_b();
        void __relay_b_to_a();
        void __stop_a_to_b();
        void __stop_b_to_a();


    protected:
        virtual void __close() = 0;
        void start_relay();


    public:
        StreamRelay();
        virtual ~StreamRelay();
}; //}

