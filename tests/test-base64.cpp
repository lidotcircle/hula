#include "../include/base64.h"
#include <iostream>
#include <assert.h>
#include <string.h>
#include <math.h>

#include <random>
static std::default_random_engine engine;
static std::uniform_int_distribution<uint8_t> dist;


void test(char* buf, size_t len) //{
{
    size_t n = std::ceil(len / 3.0) * 4;
    char* buf1 = (char*)malloc(n);
    char* buf2 = (char*)malloc(len);

    auto a = Base64Encode(buf, len, buf1, n);
    assert(a == n);
    auto b = Base64Decode(buf1, n, buf2, len);
    assert(b == len);

    assert(memcmp(buf, buf2, len) == 0);

    free(buf1); free(buf2);
} //}


int main() {
    char hello[] = "hello world! good morning";
    test(hello, sizeof(hello));

    for(int i=0;i<100;i++) {
        int j = dist(engine) + 8;
        char* buf = (char*)malloc(j);
        for(int k=0;k<j;k++)
            buf[k] = dist(engine);

        test(buf, j);
        free(buf);
    }
}

