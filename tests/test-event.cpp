#include "../include/events.h"
#include "../include/logger.h"

#include <random>


void ecb1(EventEmitter*, const std::string& e, EventArgs::Base*) {
    assert(false);
}

bool ecb2_c = false;
void ecb2(EventEmitter*, const std::string& e, EventArgs::Base*) {
    ecb2_c = true;
}

bool ecb3_c = false;
void ecb3(EventEmitter*, const std::string& e, EventArgs::Base*) {
    assert(ecb3_c == false);
    ecb3_c = true;
}


EventEmitter::EventListener drainEL;
void drain_listener(EventEmitter* em, const std::string& event, EventArgs::Base* args) //{
{
    assert(drainEL.has());
    em->remove(drainEL);
    drainEL.clear();
} //}
void data_listener(EventEmitter* em, const std::string& event, EventArgs::Base* args) //{
{
    if(drainEL.has()) return;
    drainEL = em->on("drain", drain_listener);
} //}


using dlink = DLinkedList<int>;
void test_dlink() //{
{
    dlink* h = nullptr;
    std::vector<dlink*> insert;

    for(int i=0;i<1000;i++)
        insert.push_back(DLinkedList_insert(&h, i));

    assert(DLinkedList_element_count(&h) == 1000);

    while(!insert.empty()) {
        DLinkedList_delete_target(&h, insert.back());
        insert.pop_back();
    }
    assert(h == nullptr);


    for(int i=0;i<1000;i++)
        insert.push_back(DLinkedList_insert_to_tail(&h, i));

    DLinkedList_head(&h);
    assert(h->value == 0);
    DLinkedList_tail(&h);
    assert(h->value == 999);
    assert(DLinkedList_element_count(&h) == 1000);

    while(!insert.empty()) {
        DLinkedList_delete_target(&h, insert.back());
        insert.pop_back();
    }
    assert(h == nullptr);


    for(int i=0;i<1000;i++)
        insert.push_back(DLinkedList_insert_to_head(&h, i));

    DLinkedList_head(&h);
    assert(h->value == 999);
    DLinkedList_tail(&h);
    assert(h->value == 0);
    assert(DLinkedList_element_count(&h) == 1000);

    while(!insert.empty()) {
        DLinkedList_delete_target(&h, insert.back());
        insert.pop_back();
    }
    assert(h == nullptr);


    for(int i=0;i<1000;i++)
        insert.push_back(DLinkedList_insert(&h, i));

    while(!insert.empty()) {
        DLinkedList_delete(&insert.back());
        insert.pop_back();
    }
    h = nullptr;


    for(int i=0;i<1000;i++)
        DLinkedList_insert(&h, i);
    DLinkedList_delete_all(&h);
    assert(h == nullptr);

    return;
} //}


int main()
{
    Logger::logger->disable();

    test_dlink();

    EventEmitter em;
    auto e = em.on("hello", ecb1);
    em.remove(e);

    e = em.on("hello", ecb2);
    em.emit("hello", new EventArgs::Base());
    assert(ecb2_c);

    e = em.on("world", ecb3, CB_ONCE);
    em.emit("world", new EventArgs::Base());
    em.emit("world", new EventArgs::Base());
    em.emit("world", new EventArgs::Base());
    em.emit("world", new EventArgs::Base());
    em.emit("world", new EventArgs::Base());
    assert(ecb3_c);

    em.on("data", data_listener);

    std::default_random_engine engine(1000);
    std::uniform_int_distribution<int> dist(0, 1 << 20);
    for(int i=0;i<10000;i++) {
        auto m = dist(engine);
        if(m % 2 == 0) {
            em.emit("data",  nullptr);
            assert(drainEL);
        } else {
            em.emit("drain", nullptr);
            assert(!drainEL);
        }
    }
}

