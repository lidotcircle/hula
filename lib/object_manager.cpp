#include "../include/object_manager.h"
#include "../include/logger.h"
#include "../include/config.h"

#include <assert.h>

void ObjectManager::callback_insert(UVC::Base* ptr, EventEmitter* obj) {
    assert(this->m_callbacks.find(ptr) == this->m_callbacks.end());
    assert(this->m_objects.find(obj) == this->m_objects.end() ||
           this->m_objects[obj].find(ptr) == this->m_objects[obj].end());
    this->m_callbacks[ptr] = obj;
    this->m_objects[obj].insert(ptr);
}


EventEmitter* ObjectManager::callback_remove(UVC::Base* ptr) {
    assert(this->m_callbacks.find(ptr) != this->m_callbacks.end());
    auto ret = this->m_callbacks[ptr];
    this->m_callbacks.erase(this->m_callbacks.find(ptr));
    if(ret != nullptr) {
        assert(this->m_objects.find(ret) != this->m_objects.end());
        assert(this->m_objects[ret].find(ptr) != this->m_objects[ret].end());
        this->m_objects[ret].erase(this->m_objects[ret].find(ptr));
    }
    return ret;
}

void ObjectManager::register_object(EventEmitter* obj) {
    assert(this->m_objects.find(obj) == this->m_objects.end());
    this->m_objects[obj] = std::set<UVC::Base*>();
}

void ObjectManager::callback_remove_owner(EventEmitter* obj) {
    assert(this->m_objects.find(obj) != this->m_objects.end());
    for(auto& cb: this->m_objects[obj]) {
        assert(this->m_callbacks.find(cb) != this->m_callbacks.end());
        this->m_callbacks[cb] = nullptr;
    }
    this->m_objects.erase(this->m_objects.find(obj));
}


CallbackManager::CallbackManager(): m_invalidate(false) {}
void CallbackManager::add_callback(CallbackPointer* ptr) {
    assert(this->m_list.find(ptr) == this->m_list.end());
    this->m_list.insert(ptr);
} 

void CallbackManager::remove_callback(CallbackPointer* ptr) {
    assert(this->m_list.find(ptr) != this->m_list.end());
    this->m_list.erase(this->m_list.find(ptr));
}

void CallbackManager::invalidate_callbacks() {
    assert(this->m_invalidate == false && "double invalidation is forbid");
    this->m_invalidate = true;
    for(auto& cbd: this->m_list)
        cbd->can_run = false;
}

CallbackManager::~CallbackManager() {
    this->invalidate_callbacks();
}
