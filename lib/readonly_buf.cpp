#include "../include/robuf.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <exception>

struct ROBuf_shared {
        const char* base;
        size_t ref;
        free_func free;
};

ROBuf::ROBuf(size_t size): len(size), offset(0) //{
{
    if(this->len == 0) {
        this->shared = nullptr;
        return;
    }
    this->shared = new ROBuf_shared();
    this->shared->base = (char*)malloc(this->len);
    this->shared->free = free;
    this->shared->ref = 1;
} //}
ROBuf::ROBuf(const ROBuf& origin, size_t len, int offset) //{
{
    this->offset = offset + origin.offset;
    assert(this->offset >= 0);
    this->len = len;
    this->shared = origin.shared;
    this->ref();
} //}
ROBuf::ROBuf(void* b, size_t size, size_t offset, free_func free): len(size), offset(offset) //{
{
    assert(size > 0 && size > offset);
    this->shared = new ROBuf_shared();
    this->shared->base = (char*)b;
    this->shared->free = free;
    this->shared->ref = 1;
} //}

ROBuf::ROBuf(): len(0), offset(0), shared(nullptr) {}
ROBuf::ROBuf(const ROBuf& buf) //{
{
    this->shared = buf.shared;
    this->len = buf.len;
    this->offset = buf.offset;
    this->ref();
    return;
} //}
ROBuf::ROBuf(ROBuf&& buf) //{
{
    this->shared = nullptr;
    (*this) = static_cast<ROBuf&&>(buf);
} //}

ROBuf& ROBuf::operator=(const ROBuf& buf) //{
{
    this->unref();
    this->len = buf.len;
    this->offset = buf.offset;
    this->shared = buf.shared;
    this->ref();
    return *this;
} //}
ROBuf& ROBuf::operator=(ROBuf&& buf) //{
{
    this->unref();
    this->len = buf.len;
    this->offset = buf.offset;
    this->shared = buf.shared;
    buf.shared = nullptr;
    buf.len = 0;
    buf.offset = 0;
    return *this;
} //}

void ROBuf::ref() //{
{
    if(this->shared == nullptr) return;
    ++this->shared->ref;
} //}
void ROBuf::unref() //{
{
    if(this->shared == nullptr) return;
    if(--this->shared->ref != 0) return;
    if(this->shared->free != nullptr)
        this->shared->free((char*)this->shared->base);
    delete this->shared;
} //}

ROBuf ROBuf::operator+(const ROBuf& a) const //{
{
    if(this->size() == 0) return a;
    if(a.size() == 0) return *this;
    ROBuf buf(this->size() + a.size());
    if(this->size() > 0) memcpy(buf.__base(), this->base(), this->size());
    if(a.size() > 0)     memcpy(buf.__base() + this->size(), a.base(), a.size());
    return buf;
} //}
ROBuf ROBuf::operator+(int a) const //{
{
    ROBuf buf(*this);
    buf.offset += a;
    buf.len -= a;
    if(buf.offset < 0) throw std::exception(); // FIXME
    if(buf.len < 0)    throw std::exception();
    if(buf.len == 0) return ROBuf();
    return buf;
} //}

const char*  ROBuf::base() const //{
{
    if(this->shared == nullptr) return nullptr;
    return this->shared->base + this->offset;
} //}
size_t ROBuf::size() const {return this->len;}

void ROBuf::clear_free() //{
{
    if(this->shared == nullptr) return;
    this->shared->free = nullptr;
} //}
std::tuple<free_func, char*> ROBuf::get_free() const //{
{
    if(this->shared == nullptr) return std::make_tuple(nullptr, nullptr);
    return std::make_tuple(this->shared->free, (char*)this->shared->base);
} //}

ROBuf::~ROBuf() {this->unref();}


static char __hex_code[17] = "0123456789ABCDEF";
std::ostream& operator<<(std::ostream& o, const ROBuf& b) //{
{
    size_t i;
    uint8_t m, n;
    const char* base = b.base();
    o << std::string(1, '\'');
    for(i=0; i<b.size(); i++) {
        m = (base[i] & 0xF0) >> 4;
        n = (base[i] & 0x0F);
        o << std::string("\\x") << std::string(1, __hex_code[m]) << std::string(1, __hex_code[n]);
    }
    o << std::string(1, '\'');
    return o;
} //}


