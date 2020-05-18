#include "../include/utils.h"

#include <assert.h>

#include <string>

void test_hn_convert() //{
{
    // asuming a little-endian computer
    assert(k_htons(0xFE01) == 0x01FE);
    assert(k_ntohs(0xFE01) == 0x01FE);

    assert(k_htonl(0xFE0102CC) == 0xCC0201FE);
    assert(k_ntohl(0xFE0102CC) == 0xCC0201FE);

    std::cout << "-- pass host network integer convertor test" << std::endl;
} //}

void test_ipv4_convert() //{
{
    assert(ip4_to_str(k_htonl(0xA0A1A2A3)) == std::string("160.161.162.163"));
    uint32_t test_addr;
    assert(str_to_ip4("160.161.162.163", &test_addr));
    assert(test_addr == k_htonl(0xA0A1A2A3));

    std::cout << "-- pass ipv4 string convertor test" << std::endl;
} //}

int main() //{
{
    test_hn_convert();
    test_ipv4_convert();
    return 0;
} //}

