#include "../include/kclient_manager_libuv.h"
#include "../include/ObjectFactory.h"
#include "../include/stream_libuv.h"


#define DEBUG(all...) __logger->debug(all)

NS_PROXY_CLIENT_START


ServerManagerUV::ServerManagerUV(const std::string& http_conf_file, uv_loop_t* loop): ServerManager(), m_loop(loop) //{
{
    DEBUG("call %s", FUNCNAME);

    auto tcp = new uv_tcp_t();
    uv_tcp_init(this->m_loop, tcp);
    this->post_init(http_conf_file, EBStreamUV::getWrapperFromStream(tcp));
} //}

HttpFileServer*  ServerManagerUV::createHttpFileServer(const std::string& filename, UNST connection) //{
{
    DEBUG("call %s", FUNCNAME);
    auto config = Factory::Config::createHttpFileServerConfig(filename, UVFile::loop_to_FileMechanism(this->m_loop));
    config->loadFromFile(nullptr, nullptr);
    auto es = config->getError();
    while(!es.empty()) {
        std::cout << es.top() << std::endl;
        es.pop();
    }
    auto server = Factory::Web::createHttpFileServer(connection, std::shared_ptr<HttpFileServerConfig>(config));
    return server;
} //}
WebSocketServer* ServerManagerUV::createWSSession     (UNST connection) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(connection->getType() == StreamType::LIBUV);
    return Factory::Web::createWSServer(connection);
} //}

Server* ServerManagerUV::createServer(const std::string& filename, UNST connection) //{
{
    DEBUG("call %s", FUNCNAME);
    auto config = Factory::Config::createClientConfig(filename, UVFile::loop_to_FileMechanism(this->m_loop));
    config->loadFromFile(nullptr, nullptr);
    auto server = Factory::KProxyClient::createServer(std::shared_ptr<ClientConfig>(config), connection);
    return server;
} //}


NS_PROXY_CLIENT_END

