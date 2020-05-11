#include <openssl/ssl.h>
#include <openssl/crypto.h>

#include <assert.h>

#define xassert(expr) assert(expr)

inline X509* mem2cert(void* m, size_t len) {
    X509 *cert = NULL;
    BIO* cbio = BIO_new_mem_buf(m, len);
    cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
    return cert;
}

inline RSA* mem2rsa(void* m, size_t len) {
    RSA *rsa = NULL;
    BIO* kbio = BIO_new_mem_buf(m, len);
    rsa = PEM_read_bio_RSAPrivateKey(kbio, NULL, 0, NULL);
    return rsa;
}


struct ROBuf_shared {
        void* base;
        size_t ref;
        void (*free)(ROBuf_shared*);
};


class ROBuf //{
{
    private:
        size_t len;
        size_t offset;
        ROBuf_shared* shared;

    public:
        ROBuf(size_t size);
        ROBuf(const ROBuf& origin, size_t len, int offset = 0);
        ROBuf(void* b, size_t size, size_t offset = 0, void (*free)(ROBuf_shared* b) = nullptr);
        ROBuf(const ROBuf& a, const ROBuf& b);
        
        void ref();
        void unref();

        ROBuf operator+(const ROBuf& a);

        void*  base() const;
        size_t size() const;

        ~ROBuf();
}; //}

