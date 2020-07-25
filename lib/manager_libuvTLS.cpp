#include "../include/manager_libuvTLS.h"
#include "../include/ObjectFactory.h"
#include "../include/stream_object_libuv.h"


HttpFileServer*  ResourceManagerUVTLS::createHttpFileServer(const std::string& filename, UNST con) //{
{
    assert(con->getType() == StreamType::TLS_LIBUV);
    assert(!con->is_null());

    auto ctx = EBStreamTLS::getCTXFromWrapper(con);
    EBStreamObjectUV* stream = dynamic_cast<decltype(stream)>(ctx->mp_stream);
    assert(stream);
    auto loop = stream->get_uv_loop();
    auto mec  = FileAbstraction::FileMechanism(new __UVFileMechanism(loop));
    auto config = Factory::Config::createHttpFileServerConfig(filename, mec);
    config->loadFromFile(nullptr, nullptr);

    return Factory::Web::createHttpFileServer(con, std::shared_ptr<HttpFileServerConfig>(config));
} //}
WebSocketServer* ResourceManagerUVTLS::createWSSession(UNST con) //{
{
    return nullptr;
} //}

