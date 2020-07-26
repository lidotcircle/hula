#include "../include/kclient_manager.h"
#include "../include/config.h"


NS_PROXY_CLIENT_START


ServerManager::ServerManager(): KManager(CLIENT_DEFAULT_CONFIG_DIR, CLIENT_DEFAULT_CONFIG_NAME) //{
{
} //}
void ServerManager::start() //{
{
#define REGISTER_FCALL(fname) this->register_dispatch(#fname, fname);
    CLIENT_RPC_LIST(REGISTER_FCALL)
#undef  REGISTER_FCALL
    this->KManager<KProxyClient::Server>::start();
} //}

#define GETTHIS() \
    auto __this = arg->GetThis(); \
    ServerManager* _this = dynamic_cast<decltype(_this)>(__this); assert(_this); \
    auto argc  = arg->GetArgc()
/** [static] */
void ServerManager::NEW_INSTANCE(RequestArg arg) //{
{
    GETTHIS();
    if(arg->GetArgc() != 1)
        return arg->fail(std::string(__func__) + ": bad arguments, required 1");

    int id = atoi(arg->GetArg(0).c_str());
    if(!_this->has_config(id))
        return arg->fail(std::string(__func__) + ": config " + std::to_string(id) + " doesn't exist");

    int ret = _this->new_server(id);
    if(ret < 0)
        return arg->fail(std::string(__func__) + ": create a new instance fault");

    arg->success(std::to_string(ret));
} //}
void ServerManager::CLOSE_INSTANCE(RequestArg arg) //{
{
    GETTHIS();
    if(arg->GetArgc() != 1)
        return arg->fail(std::string(__func__) + ": bad arguments, required 1");

    int id = atoi(arg->GetArg(0).c_str());
    if(!_this->has_server(id))
        return arg->fail(std::string(__func__) + ": server " + std::to_string(id) + " doesn't exist");

    _this->shutdown_server(id);
    return arg->success("");
} //}
void ServerManager::GET_INSTANCES_STATUS(RequestArg arg) //{
{
    arg->fail("unimplemented");
} //}

/** [static] */
void ServerManager::GET_CONFIG_LIST(RequestArg arg) //{
{
    arg->fail("unimplemented");
} //}
void ServerManager::ADD_CONFIG(RequestArg arg) //{
{
    arg->fail("unimplemented");
} //}
void ServerManager::DELETE_CONFIG(RequestArg arg) //{
{
    arg->fail("unimplemented");
} //}
void ServerManager::RENAME_CONFIG(RequestArg arg) //{
{
    arg->fail("unimplemented");
} //}
#undef  GETTHIS


NS_PROXY_CLIENT_END

