#pragma once

// #include <unordered_map>
#include <map>
#include <tuple>
#include <vector>

class EventEmitter;

enum CBFlags: uint8_t {
    CB_NONE = 0,
    CB_ONCE = 1
};

struct CBList {
    CBList* next;
    CBList* prev;
    void*   cb; // callback
    CBFlags flags;
};

namespace EventArgs {
struct Base {inline virtual ~Base() {};};
}

typedef void (*EventCallback)(EventEmitter* target, const std::string& event, EventArgs::Base* argv);

class EventEmitter {
    private:
        std::map<std::string, CBList*> m_listeners;

    public:
        void* on(const std::string&, EventCallback cb, CBFlags flags = CB_NONE);
        void  emit(const std::string&, EventArgs::Base* argv);
        void  remove(void*);
        void  removeall();

        inline virtual ~EventEmitter() {}
};

