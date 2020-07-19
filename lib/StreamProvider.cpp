#include "../include/StreamProvider.h"
#include "../include/config.h"

#include <assert.h>


#define DEBUG(all...) __logger->debug(all)


static void dummy_free_bool(void* m) {delete static_cast<bool*>(m);}
StreamProvider::StreamId StreamProvider::init(EBStreamAbstraction* stream) //{
{
    DEBUG("call %s", FUNCNAME);
    bool* runlock = new bool(true);
    assert(this->m_run_lock.find(stream) == this->m_run_lock.end());
    this->m_run_lock[stream] = runlock;
    return this->createStreamID(runlock, dummy_free_bool, stream);
} //}
void StreamProvider::finish(EBStreamAbstraction* stream) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_run_lock.find(stream) != this->m_run_lock.end());
    this->m_run_lock.erase(this->m_run_lock.find(stream));
} //}

StreamProvider::~StreamProvider() //{
{
    DEBUG("call %s", FUNCNAME);
    for(auto& x: this->m_run_lock) *x.second = false;
} //}

