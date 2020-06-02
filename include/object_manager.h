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

