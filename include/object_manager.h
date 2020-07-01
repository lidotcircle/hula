#pragma once

#include <map>
#include <set>

namespace UVC { class Base; }
class EventEmitter;

class ObjectManager {
    private:
        std::map<UVC::Base*, EventEmitter*> m_callbacks;
        std::map<EventEmitter*, std::set<UVC::Base*>> m_objects;

    public:
        void          callback_insert(UVC::Base* ptr, EventEmitter* obj);
        EventEmitter* callback_remove(UVC::Base* ptr);
        void          register_object(EventEmitter* obj);
        void          callback_remove_owner(EventEmitter* obj);
        inline size_t CallbackLength() {return this->m_callbacks.size();}
};

class CallbackManager;
class CallbackPointer {
    private:
        bool can_run;
        friend class CallbackManager;

    public:
        inline CallbackPointer(): can_run(true) {}
        inline virtual ~CallbackPointer() {};
        inline bool CanRun() {return this->can_run;}
};

class CallbackManager {
    private:
        std::set<CallbackPointer*> m_list;
        bool m_invalidate;
        void invalidate_callbacks();
        
    public:
        CallbackManager();
        void add_callback(CallbackPointer* ptr);
        void remove_callback(CallbackPointer* ptr);
        ~CallbackManager();
};

