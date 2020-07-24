#include "../include/http_file_server_libuv.h"
#include "../include/ObjectFactory.h"


UVHttpFileServer::UVHttpFileServer(std::shared_ptr<HttpFileServerConfig> config, uv_tcp_t* tcp): //{
    HttpFileServer(config), EBStreamUV(tcp)
{
    this->mp_loop = uv_handle_get_loop((uv_handle_t*)tcp);
} //}

Http*            UVHttpFileServer::createHttpSession(UNST con) //{
{
    return Factory::Web::createHttpSession(con);
} //}
FileAbstraction* UVHttpFileServer::createFile(const std::string& filename) //{
{
    return Factory::Filesystem::createUVFile(filename, this->mp_loop);
} //}

