#include "../include/manager_libuv.h"
#include "../include/ObjectFactory.h"


HttpFileServer*  ResourceManagerUV::createHttpFileServer(const std::string& filename, UNST con) //{
{
    assert(con->getType() == StreamType::LIBUV);
    assert(!con->is_null());
    auto tcp = EBStreamUV::getStreamFromWrapper(con);
    auto loop = uv_handle_get_loop((uv_handle_t*)tcp);
    auto mec  = FileAbstraction::FileMechanism(new __UVFileMechanism(loop));
    auto config = Factory::Config::createHttpFileServerConfig(filename, mec);
    config->loadFromFile(nullptr, nullptr);

    return Factory::Web::createHttpFileServer(con, std::shared_ptr<HttpFileServerConfig>(config));
} //}
WebSocketServer* ResourceManagerUV::createWSSession(UNST con) //{
{
    return nullptr;
} //}

