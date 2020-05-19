#include "../include/socks5.h"
#include "../include/utils.h"
#include "../include/config.h"


std::tuple<bool, struct __client_selection_msg, ROBuf> parse_client_hello(ROBuf remain, ROBuf income) //{
{
    __logger->debug("call parse_client_hello(remain.size=%d, income.size=%d)", remain.size(), income.size());
    assert(income.size() > 0); 
    ROBuf merge = remain + income;
    __client_selection_msg msg;
    msg.m_version = merge.base()[0];
    uint8_t i = merge.base()[1];
    __logger->debug("         methods: %d", i);
    if(merge.size() < i + 2) return std::make_tuple(false, msg, ROBuf());
    for(int j = 2; i > 0; i--, j++)
        msg.m_methods.push_back(merge.base()[j]);
    if(msg.m_methods.size() > 0) 
        __logger->debug("         first method: %d", msg.m_methods[0]);
    return std::make_tuple(true, msg, merge + 2 + msg.m_methods.size());
} //}

std::tuple<bool, struct __client_request_msg, ROBuf, bool> parse_client_request(ROBuf remain, ROBuf income) //{
{
    __logger->debug("call parse_client_request(remain.size=%d, income.size=%d)", remain.size(), income.size());
    assert(income.size() > 0);
    bool result = true;
    bool packet_error = false;
    __client_request_msg msg;
    int inc = 4;
    ROBuf merge = remain + income;
    if(merge.size() < 4) {
        result = false;
        goto __RETURN;
    }
    msg.m_version = merge.base()[0];
    msg.m_command = (socks5_command_type)merge.base()[1];
    msg.m_reserved = 0;
    msg.m_addr_type = (socks5_addr_type)merge.base()[3];
    uint32_t addr_ipv4;
    uint8_t  addr_len;
    char*    addr_domain;
    switch(msg.m_addr_type) {
        case SOCKS5_ADDR_IPV4:
            if(10 > merge.size()) {
                result = false;
                break;
            }
            addr_len = 3;
            addr_ipv4 = *(uint32_t*)&merge.base()[4];
            msg.m_addr = std::string(ip4_to_str(addr_ipv4));
            inc += 4;
            break;
        case SOCKS5_ADDR_DOMAIN:
            addr_len = merge.base()[4];
            if(addr_len + 7 > merge.size()) {
                result = false;
                break;
            }
            addr_domain = (char*)malloc(addr_len + 1);
            addr_domain[addr_len] = 0;
            memcpy(addr_domain, merge.base() + 5, addr_len);
            msg.m_addr = std::string(addr_domain);
            free(addr_domain);
            inc += 1 + addr_len;
            break;
        case SOCKS5_ADDR_IPV6: // TODO
        default:
            packet_error = true;
            break;
    }
    if(result && packet_error == false) {
        msg.m_port = *(uint16_t*)&merge.base()[addr_len + 1 + 4];
        inc += 2;
    }
__RETURN:
    __logger->debug("parse_client_request() error=%d, return with (addr=%s, port=%d, addr_type=%d, cmd=%d)", 
            packet_error, msg.m_addr.c_str(), k_ntohs(msg.m_port), msg.m_addr_type, msg.m_command);
    return std::make_tuple(result, msg, merge + inc, packet_error);
} //}

std::tuple<bool, struct __socks5_username_password, ROBuf> parse_username_authentication(ROBuf remain, ROBuf income) //{
{
    __logger->debug("call parse_username_authentication()");
    __socks5_username_password pair;
    bool result = true;
    ROBuf merge = remain + income;
    uint8_t u_len, p_len;
    int inc = 2;
    if(merge.size() <= inc) {
        result = false;
        goto __RETURN;
    }

    pair.m_version = merge.base()[0];
    u_len = merge.base()[1];
    if(u_len + 4 <= merge.size()) {
        char* u_str = (char*)malloc(u_len + 1);
        u_str[u_len] = 0;
        memcpy(u_str, merge.base() + 2, u_len);
        pair.m_username = std::string(u_str);
        free(u_str);
        inc += u_len + 1;
    } else {
        result = false;
        goto __RETURN;
    }

    p_len = merge.base()[u_len + 2];
    if(u_len + p_len + 3 <= merge.size()) {
        char* p_str = (char*)malloc(p_len + 1);
        p_str[p_len] = 0;
        memcpy(p_str, merge.base() + 3 + u_len, p_len);
        pair.m_password = std::string(p_str);
        free(p_str);
        inc += p_len;
    }

__RETURN:
    __logger->debug("parse_username_authentication()  username=%s, password=%s", pair.m_username.c_str(), pair.m_password.c_str());
    return std::make_tuple(result, pair, merge + inc);
} //}

