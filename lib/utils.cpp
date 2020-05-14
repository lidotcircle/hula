#include <openssl/ssl.h>
#include <openssl/crypto.h>

#include <assert.h>
#include "../include/utils.h"

/** global logger */
Logger::Logger logger("kproxy", "./kproxy.log");


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

