#include "../include/http_file_server_libuvTLS.h"
#include "../include/ObjectFactory.h"
#include "../include/stream_object_libuv.h"


UVTLSHttpFileServer::UVTLSHttpFileServer(std::shared_ptr<HttpFileServerConfig> config, UNST tlscon): //{
    HttpFileServer(config), EBStreamUVTLS(tlscon)
{
    auto aa = EBStreamUVTLS::getCTXFromWrapper(tlscon);
    EBStreamObjectUV* uvstream = dynamic_cast<decltype(uvstream)>(aa->mp_stream);
    assert(uvstream);
    this->mp_loop = uvstream->get_uv_loop();
} //}
UVTLSHttpFileServer::UVTLSHttpFileServer(std::shared_ptr<HttpFileServerConfig> config, uv_tcp_t* tcp, //{
        const std::string& cert, const std::string& privateKey):
    HttpFileServer(config), EBStreamUVTLS(EBStreamUVTLS::createUnderlyingStream(tcp, TLSMode::ServerMode, cert, privateKey))
{
    this->mp_loop = uv_handle_get_loop((uv_handle_t*)tcp);
} //}

Http*            UVTLSHttpFileServer::createHttpSession(UNST con) //{
{
    return Factory::Web::createHttpSession(con);
} //}
FileAbstraction* UVTLSHttpFileServer::createFile(const std::string& filename) //{
{
    return Factory::Filesystem::createUVFile(filename, this->mp_loop);
} //}

