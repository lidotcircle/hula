#pragma once

// #include <unordered_map>
#include <map>
#include <tuple>
#include <vector>

#include "dlinkedlist.hpp"

class EventEmitter;


namespace EventArgs {struct Base {inline virtual ~Base() {};};}


typedef void (*EventCallback)(EventEmitter* target, const std::string& event, EventArgs::Base* argv);
enum CBFlags: uint8_t {CB_NONE = 0,CB_ONCE = 1};

struct CallbackState {
    EventCallback cb;
    CBFlags       flags;
};
using CBList = DLinkedList<CallbackState>;


class EventEmitter {
    private:
        std::map<std::string, CBList*> m_listeners;
        void delete_all();

    public:
        void* on(const std::string&, EventCallback cb, CBFlags flags = CB_NONE);
        void  emit(const std::string&, EventArgs::Base* argv);
        void  remove(void*);
        void  removeall();

        virtual ~EventEmitter();
};

