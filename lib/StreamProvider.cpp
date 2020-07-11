#include "../include/StreamProvider.h"

#include <assert.h>


static void dummy_free_bool(void* m) {delete static_cast<bool*>(m);}
StreamProvider::StreamId StreamProvider::init(EBStreamAbstraction* stream) //{
{
    bool* runlock = new bool(true);
    assert(this->m_run_lock.find(stream) == this->m_run_lock.end());
    this->m_run_lock[stream] = runlock;
    return this->createStreamID(runlock, dummy_free_bool, stream);
} //}
void StreamProvider::finish(EBStreamAbstraction* stream) //{
{
    assert(this->m_run_lock.find(stream) != this->m_run_lock.end());
    this->m_run_lock.erase(this->m_run_lock.find(stream));
} //}

StreamProvider::~StreamProvider() //{
{
    for(auto& x: this->m_run_lock) *x.second = false;
} //}

