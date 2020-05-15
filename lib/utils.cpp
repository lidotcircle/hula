#include <openssl/ssl.h>    // conflict with uv.h
#include <openssl/crypto.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../include/utils.h"

/** global logger */
Logger::Logger* logger = new Logger::Logger("kproxy", "./kproxy.log");


X509* mem2cert(void* m, size_t len) //{
{
    X509 *cert = NULL;
    BIO* cbio = BIO_new_mem_buf(m, len);
    cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
    return cert;
} //}
RSA* mem2rsa(void* m, size_t len) //{
{
    RSA *rsa = NULL;
    BIO* kbio = BIO_new_mem_buf(m, len);
    rsa = PEM_read_bio_RSAPrivateKey(kbio, NULL, 0, NULL);
    return rsa;
} //}

static union {uint16_t u16; uint8_t u8;} bytes_endian_test = {.u16 = 0xFFEE};
static bool little_endian() {return bytes_endian_test.u8 == 0xEE;}
struct _ipv4_addr {uint8_t a, b, c, d;};
struct __int_16 {uint8_t a, b;};
static char ipv4str[20];
char* ip4_to_str(uint32_t addr) //{
{
    uint32_t t = k_htonl(addr);
    _ipv4_addr* x = (_ipv4_addr*)&t;
    sprintf(ipv4str, "%d.%d.%d.%d", x->a, x->b, x->c, x->d);
    return ipv4str;
} //}
bool str_to_ip4(const char* str, uint32_t* out) //{
{
    size_t l = 0;
    uint8_t dot = 0;
    uint8_t dot_p[3];
    while(str[l] != '\0') {
        if(l > 19) return false; // 4 * 4 + 3 = 19
        if(str[l] < '0' || str[l] > '9') {
            if(str[l] != '.') return false;
            if(dot == 3) return false;
            dot_p[dot] = l;
            dot++;
        }
        l++;
    }
    if(dot != 3) return false;
    if(dot_p[0] == 0 || dot_p[2] + 1 == strlen(str)) return false;

    if(dot_p[0] - 0        > 3 || 
       dot_p[1] - dot_p[0] > 3 || 
       dot_p[2] - dot_p[1] > 3)
        return false;

    char copyx[20];
    strcpy(copyx, str);
    copyx[dot_p[0]] = 0;
    copyx[dot_p[1]] = 0;
    copyx[dot_p[2]] = 0;
    dot_p[0]++;
    dot_p[1]++;
    dot_p[2]++;

    _ipv4_addr addr;
    addr.a = atoi(copyx + 0);
    addr.b = atoi(copyx + dot_p[0]);
    addr.c = atoi(copyx + dot_p[1]);
    addr.d = atoi(copyx + dot_p[2]);

    *out = k_ntohl(*(uint32_t*)&addr);
    return true;
} //}

uint32_t k_htonl(uint32_t v) //{
{
    if(little_endian()) {
        _ipv4_addr vx;
        *(uint32_t*)&vx = v;
        uint8_t t = vx.a;
        vx.a = vx.d; vx.d = t;
        t = vx.b;
        vx.b = vx.c; vx.c = t;
        return *(uint32_t*)&vx;
    } else {
        return v;
    }
} //}
uint32_t k_ntohl(uint32_t v) //{
{
    if(little_endian()) {
        _ipv4_addr vx;
        *(uint32_t*)&vx = v;
        uint8_t t = vx.a;
        vx.a = vx.d; vx.d = t;
        t = vx.b;
        vx.b = vx.c; vx.c = t;
        return *(uint32_t*)&vx;
    } else {
        return v;
    }
} //}
uint16_t k_htons(uint16_t v) //{
{
    if(little_endian()) {
        __int_16 vx;
        *(uint16_t*)&vx = v;
        uint8_t t = vx.a;
        vx.a = vx.b; vx.a = t;
        return *(uint16_t*)&vx;
    } else {
        return v;
    }
} //}
uint16_t k_ntohs(uint16_t v) //{
{
    if(little_endian()) {
        __int_16 vx;
        *(uint16_t*)&vx = v;
        uint8_t t = vx.a;
        vx.a = vx.b; vx.a = t;
        return *(uint16_t*)&vx;
    } else {
        return v;
    }
} //}

