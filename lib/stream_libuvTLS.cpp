#include "../include/stream_libuvTLS.h"
#include "../include/ObjectFactory.h"

#define STREAM_BUFFER_SIZE (1024 * 1024 * 2)


EBStreamUVTLS::EBStreamUVTLS(UNST stream, TLSMode mode, const std::string& cert, const std::string& privateKey): //{
    EBStreamTLS(mode, cert, privateKey)
{
    if(mode == TLSMode::ServerMode)
        assert(cert.size() > 0 && privateKey.size() > 0);
    assert(stream->getType() == StreamType::LIBUV);
    this->init_this(stream);
} //}

EBStreamUVTLS::EBStreamUVTLS(uv_tcp_t* stream, TLSMode mode, const std::string& cert, const std::string& privateKey): //{
    EBStreamTLS(mode, cert, privateKey)
{
    if(mode == TLSMode::ServerMode)
        assert(cert.size() > 0 && privateKey.size() > 0);
    this->init_this(EBStreamUV::getWrapperFromStream(stream));
} //}

EBStreamUVTLS::EBStreamUVTLS(UNST stream): //{
    EBStreamTLS(stream)
{
    assert(stream->getType() == this->getType());
} //}

EBStreamObject* EBStreamUVTLS::getStreamObject(UNST stream) //{
{
    assert(stream->getType() == StreamType::LIBUV);
    return Factory::createUVStreamObject(STREAM_BUFFER_SIZE, stream);
} //}
StreamType EBStreamUVTLS::getType() {return StreamType::TLS_LIBUV;}

/** [static] */
EBStreamUVTLS::UNST EBStreamUVTLS::createUnderlyingStream(uv_tcp_t* tcp, TLSMode mode, //{
        const std::string& cert, const std::string& privateKey)
{
    auto stream = Factory::createUVStreamObject(STREAM_BUFFER_SIZE, EBStreamUV::getWrapperFromStream(tcp));
    auto ctx = EBStreamTLS::getCTX(mode, stream, cert, privateKey);
    return UNST(new TLSUS(StreamType::TLS_LIBUV, ctx));
} //}

