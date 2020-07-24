#include "../include/base64.h"
#include <iostream>
#include <assert.h>
#include <string.h>


int main() {
    char hello[] = "hello world! good morning";
    char obuf[1000];
    char obuf2[1000];

    int a = Base64Encode(hello, strlen(hello), obuf, sizeof(obuf));
    obuf[a] = 0;
    assert(a > 0);

    std::cout << a << std::endl;
    std::cout << obuf << std::endl;

    int b = Base64Decode(obuf, a, obuf2, sizeof(obuf2));
    obuf2[b] = 0;
    assert(b > 0);

    std::cout << b << std::endl;
    std::cout << obuf2 << std::endl;
}

