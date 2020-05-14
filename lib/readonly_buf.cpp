#include "../include/robuf.h"
#include <stdlib.h>
#include <string.h>

void robuf_free(ROBuf_shared* b)
{
    free(b->base);
    return;
};

ROBuf::ROBuf(size_t size): len(size), offset(0) 
{
    this->shared = (ROBuf_shared*)malloc(sizeof(ROBuf_shared));
    this->shared->base = (void*)malloc(this->len);
    this->shared->free = robuf_free;
    this->shared->ref = 0;
    this->ref();
}

ROBuf::ROBuf(const ROBuf& origin, size_t len, int offset) 
{
    this->offset = offset + origin.offset;
    this->len = len;
    this->shared = origin.shared;
    this->ref();
}

ROBuf::ROBuf(void* b, size_t size, size_t offset, void (*free)(ROBuf_shared* b)): len(size), offset(offset)
{
    this->shared = (ROBuf_shared*)malloc(sizeof(ROBuf_shared));
    this->shared->base = b;
    this->shared->free = free;
    this->shared->ref = 0;
    this->ref();
}

ROBuf::ROBuf(const ROBuf& a, const ROBuf& b): len(a.size() + b.size()), offset(0)
{
    this->shared = (ROBuf_shared*)malloc(sizeof(ROBuf_shared));
    this->shared->free = robuf_free;
    this->shared->ref = 0;
    this->ref();

    memcpy(this->base(), a.base(), a.size());
    memcpy((char*)this->base() + a.size(), b.base(), b.size());
}

void ROBuf::ref()   {++this->shared->ref;}
void ROBuf::unref() 
{
    if(--this->shared->ref != 0) return;
    if(this->shared->free == nullptr)
        free(this->shared->base);
    else
        this->shared->free(this->shared);
}

ROBuf ROBuf::operator+(const ROBuf& a) {return ROBuf(*this, a);}

void*  ROBuf::base() const {return (char*)this->shared->base + this->offset;}
size_t ROBuf::size() const {return this->len;}

ROBuf::~ROBuf() {}

