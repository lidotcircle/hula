#include "../include/events.h"

#include <assert.h>


const auto& CBList_insert         = DLinkedList_insert<CallbackState>;
const auto& CBList_delete         = DLinkedList_delete<CallbackState>;
const auto& CBList_delete_all     = DLinkedList_delete_all<CallbackState>;
const auto& CBList_head           = DLinkedList_head<CallbackState>;
const auto& CBList_tail           = DLinkedList_tail<CallbackState>;
const auto& CBList_insert_to_head = DLinkedList_insert_to_head<CallbackState>;
const auto& CBList_insert_to_tail = DLinkedList_insert_to_tail<CallbackState>;


void  EventEmitter::delete_all() //{
{
    for(auto& cbs: this->m_listeners)
        CBList_delete_all(&cbs.second);
} //}

void* EventEmitter::on(const std::string& event, EventCallback cb, CBFlags flags) //{
{
    if(this->m_listeners.find(event) == this->m_listeners.end())
        this->m_listeners[event] = nullptr;
    CBList_insert_to_tail(&this->m_listeners[event], {cb, flags});
    auto x = this->m_listeners[event];
    CBList_tail(&x);
    return x;
} //}
void  EventEmitter::emit(const std::string& event, EventArgs::Base* argv) //{
{
    if(this->m_listeners.find(event) == this->m_listeners.end()) return;
    CBList_head(&this->m_listeners[event]);
    CBList* h = this->m_listeners[event];
    while(h != nullptr) {
        EventCallback ccb = (EventCallback)h->value.cb;
        assert(ccb != nullptr);
        ccb(this, event, argv);
        if((h->value.flags & CB_ONCE) != 0) { // delete callback;
            bool prev = h->prev != nullptr;
            CBList_delete(&h);
            if(prev) h = h->next;
        } else {
            h = h->next;
        }
    }
} //}
void  EventEmitter::remove(void* l) //{
{
    assert(l != nullptr);
    CBList_delete((CBList**)&l);
} //}
void  EventEmitter::removeall() //{
{
    this->delete_all();
    this->m_listeners.clear();
} //}

EventEmitter::~EventEmitter() //{
{
    this->delete_all();
} //}

