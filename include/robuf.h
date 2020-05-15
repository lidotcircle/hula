#pragma once

#include <tuple>

#include <stdlib.h>

typedef void (*free_func)(void*);

struct ROBuf_shared;

class ROBuf //{
{
    private:
        size_t len;
        size_t offset;
        ROBuf_shared* shared;

        void ref();
        void unref();

    public:
        ROBuf();
        ROBuf(const ROBuf&);
        ROBuf(ROBuf&&);

        ROBuf& operator=(const ROBuf&);
        ROBuf& operator=(ROBuf&&);

        ROBuf(size_t size);
        ROBuf(const ROBuf& origin, size_t len, int offset = 0);
        ROBuf(void* b, size_t size, size_t offset = 0, free_func free = nullptr);

        ROBuf operator+(const ROBuf& a) const;

        const char* base() const;
        inline char* __base() const {return const_cast<char*>(this->base());};
        size_t size() const;

        inline bool empty() const {return this->shared == nullptr;}
        void clear_free();
        std::tuple<free_func, char*> get_free() const;

        ~ROBuf();
}; //}

