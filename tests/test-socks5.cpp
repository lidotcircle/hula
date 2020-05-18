#include "../include/socks5.h"


void test_hello() //{
{
    auto x = parse_client_hello(ROBuf((void*)"\x05", 1), ROBuf((void*)"\x03\x00\x01\x02\x00", 5));

    bool result;
    __client_selection_msg msg;
    ROBuf remain;

    std::tie(result, msg, remain) = x;

    assert(result);
    assert(msg.m_version = 5 && msg.m_methods.size() == 3);
    assert(remain.size() == 1);
} //}

void test_client_request() //{
{
    auto x = parse_client_request(ROBuf((void*)"\x05", 1), ROBuf((void*)"\x01\x00\x01\x02\x00", 5));

    bool result;
    __client_request_msg msg;
    ROBuf remain;
    bool error;

    std::tie(result, msg, remain, error) = x;

    assert(!result);
    assert(!error);

    x = parse_client_request(ROBuf((void*)"\x05", 1), ROBuf((void*)"\x01\x00\x01\x02\x01\x01\x01\x11\x11", 9));
    std::tie(result, msg, remain, error) = x;
    assert(result);
    assert(!error);
    assert(msg.m_version == 5 && msg.m_addr == "2.1.1.1" &&
           msg.m_port == 0x1111 && msg.m_command == SOCKS5_CMD_CONNECT &&
           msg.m_addr_type == SOCKS5_ADDR_IPV4);

    x = parse_client_request(ROBuf((void*)"\x05", 1), ROBuf((void*)"\x01\x00\x04\x02\x01\x01\x01\x11\x11", 9));
    std::tie(result, msg, remain, error) = x;
    assert(error);

    x = parse_client_request(ROBuf((void*)"\x05", 1), ROBuf((void*)"\x01\x00\x03\x0Fwww.example.com\x11\x11", 21));
    std::tie(result, msg, remain, error) = x;
    assert(result);
    assert(!error);
    assert(remain.size() == 0);
    assert(msg.m_addr == "www.example.com");
} //}

void test_client_username_password() //{
{
    auto x = parse_username_authentication(ROBuf((void*)"\x05\x03", 2), ROBuf((void*)"goo\x04haha", 8));

    bool result;
    __socks5_username_password msg;
    ROBuf remain;

    std::tie(result, msg, remain) = x;

    assert(result);
    assert(msg.m_version = 5 && msg.m_username == "goo" && 
           msg.m_password == "haha");
    assert(remain.size() == 0);
} //}

int main() //{
{
    test_hello(); std::cout << "-- pass client hello test" << std::endl;
    test_client_request(); std::cout << "-- pass client request test" << std::endl;
    test_client_username_password(); std::cout << "-- pass client username password test" << std::endl;
} //}

