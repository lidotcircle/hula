#include "../include/events.h"

#include <assert.h>


void CBList_insert(CBList** cbl, EventCallback cb, CBFlags flags) //{
{
    CBList* new_entry = new CBList();
    new_entry->cb = (void*)cb;
    new_entry->flags = flags;
    new_entry->next = nullptr;
    new_entry->prev = nullptr;

    if(*cbl == nullptr) {
        *cbl = new_entry;
        return;
    }

    CBList* cbl_next = (*cbl)->next;

    (*cbl)->next = new_entry;
    new_entry->prev = *cbl;

    if(cbl_next != nullptr) {
        cbl_next->prev = new_entry;
        new_entry->next = cbl_next;
    }
    return;
} //}
void CBList_delete(CBList** cbl) //{
{
    assert(*cbl != nullptr);

    CBList* cbl_prev = (*cbl)->prev;
    CBList* cbl_next = (*cbl)->next;

    delete *cbl;

    *cbl = nullptr;

    if(cbl_prev != nullptr) {
        cbl_prev->next = cbl_next;
        *cbl = cbl_prev;
    }
    if(cbl_next != nullptr) {
        cbl_next->prev = cbl_prev;
        if(*cbl == nullptr) *cbl = cbl_next;
    }
    return;
} //}
void CBList_head(CBList** cbl) //{
{
    CBList* c = *cbl;
    if(c == nullptr) return;
    while(c->prev != nullptr)
        c = c->prev;
    *cbl = c;
} //}
void CBList_tail(CBList** cbl) //{
{
    CBList* c = *cbl;
    if(c == nullptr) return;
    while(c->next != nullptr)
        c = c->next;
    *cbl = c;
} //}
void CBList_insert_to_head(CBList** cbl, EventCallback cb, CBFlags flags) //{
{
    CBList_head(cbl);
    CBList* new_entry = new CBList();
    new_entry->cb = (void*)cb;
    new_entry->flags = flags;
    new_entry->prev = nullptr;
    new_entry->next = nullptr;
    
    CBList* old_head = *cbl;
    *cbl = new_entry;
    new_entry->next = old_head;
    if(old_head != nullptr)
        old_head->prev = new_entry;
} //}
void CBList_insert_to_tail(CBList** cbl, EventCallback cb, CBFlags flags) //{
{
    CBList_tail(cbl);
    CBList* new_entry = new CBList();
    new_entry->cb = (void*)cb;
    new_entry->flags = flags;
    new_entry->prev = nullptr;
    new_entry->next = nullptr;
    
    CBList* old_tail = *cbl;
    *cbl = new_entry;
    new_entry->prev = old_tail;
    if(old_tail != nullptr)
        old_tail->next = new_entry;
} //}

void* EventEmitter::on(const std::string& event, EventCallback cb, CBFlags flags) //{
{
    if(this->m_listeners.find(event) == this->m_listeners.end())
        this->m_listeners[event] = nullptr;
    CBList_insert_to_tail(&this->m_listeners[event], cb, flags);
    auto x = this->m_listeners[event];
    CBList_tail(&x);
    return x;
} //}
void  EventEmitter::emit(const std::string& event, void* argv) //{
{
    if(this->m_listeners.find(event) == this->m_listeners.end()) return;
    CBList_head(&this->m_listeners[event]);
    CBList* h = this->m_listeners[event];
    while(h != nullptr) {
        EventCallback ccb = (EventCallback)h->cb;
        assert(ccb != nullptr);
        ccb(this, event, argv);
        if((h->flags & CB_ONCE) != 0) { // delete callback;
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
    this->m_listeners.clear();
} //}

