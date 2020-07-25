#include "../include/kclient_manager.h"
#include "../include/config.h"

#include <filesystem>
#include <fstream>


NS_PROXY_CLIENT_START


ServerManager::ServerManager(): m_dispatch_funcs(), m_servers(), m_config_server() //{
{
    this->m_servers_inc = 1;
    this->m_configs_inc = 1;
} //}

void ServerManager::start() //{
{
#define REGISTER_CALL(fname) this->register_dispatch(#fname, fname);
    CLIENT_RPC_LIST(REGISTER_CALL);
#undef  REGISTER_CALL
    this->rescan_configs();
    assert(this->m_configs.size() > 0);
    this->new_server(this->m_configs.begin()->first);
} //}

int ServerManager::new_server(int config_id) //{
{
    assert(this->m_configs.find(config_id) != this->m_configs.end());
    auto filename = this->m_configs[config_id];
    auto s = this->createServer(filename, this->NewUNST());
    auto id = this->m_servers_inc++;
    this->m_servers[id] = std::make_pair(config_id, s);

    if(this->m_config_server.find(config_id) == this->m_config_server.end())
        this->m_config_server[config_id] = std::set<int>();
    this->m_config_server[config_id].insert(id);

    return id;
} //}
void ServerManager::shutdown_server(int server_id) //{
{
    assert(this->m_servers.find(server_id) != this->m_servers.end());
    auto cc = this->m_servers[server_id];
    this->m_servers.erase(this->m_servers.find(server_id));
    assert(this->m_config_server.find(cc.first) != this->m_config_server.end());
    assert(this->m_config_server[cc.first].find(server_id) != this->m_config_server[cc.first].end());
    this->m_config_server[cc.first].erase(this->m_config_server[cc.first].find(server_id));

    cc.second->close();
    delete cc.second;
} //}

void ServerManager::rescan_configs() //{
{
    std::filesystem::path config_dir = CLIENT_DEFAULT_CONFIG_DIR;
    if(!std::filesystem::is_directory(config_dir))
        return;

    std::vector<std::filesystem::path> files;
    std::filesystem::directory_iterator diter(config_dir, std::filesystem::directory_options::skip_permission_denied);
    while(diter != std::filesystem::end(diter)) {
        auto ff = *diter;
        if(ff.is_regular_file() && ff.path().extension() == ".conf")
            files.push_back(ff.path());
    }

    for(auto& file: files) {
        bool v = true;
        for(auto& cc: this->m_configs) {
            if(cc.second == file) {
                v = false;
                break;
            }
        }
        if(v)
            this->m_configs[this->m_configs_inc++] = file;
    }
} //}
bool ServerManager::add_config(const std::string& filename, const std::string& config) //{
{
    auto id = this->m_configs_inc++;

    std::filesystem::path p = CLIENT_DEFAULT_CONFIG_DIR;
    p.append(filename);
    assert(p.extension() == ".conf");

    if(std::filesystem::exists(p))
        return false;

    std::fstream file(p, std::ios_base::out);
    if(!file.is_open())
        return false;

    file << config << std::endl;
    this->m_configs[id] = p;
    return true;
} //}
bool ServerManager::delete_config  (int config_id) //{
{
    assert(this->m_configs.find(config_id) != this->m_configs.end());
    auto filename = this->m_configs[config_id];
    this->m_configs.erase(this->m_configs.find(config_id));

    assert(this->m_config_server.find(config_id) != this->m_config_server.end());
    auto servers = this->m_config_server[config_id];
    for(auto& s: servers)
        this->shutdown_server(s);
    assert(this->m_config_server[config_id].size() == 0);
    this->m_config_server.erase(this->m_config_server.find(config_id));

    return std::filesystem::remove(filename);
} //}
bool ServerManager::rename_config(int config_id, const std::string& newname) //{
{
    assert(this->m_configs.find(config_id) != this->m_configs.end());
    auto filename = this->m_configs[config_id];
    std::filesystem::path pp = filename;
    std::error_code error;
    std::filesystem::rename(pp, pp.parent_path().append(newname), error);
    if(error)
        return false;

    this->m_configs[config_id] = pp.parent_path().append(newname);
    return true;
} //}

void ServerManager::register_dispatch(const std::string& fname, DispatchFunc func) //{
{
    assert(this->m_dispatch_funcs.find(fname) == this->m_dispatch_funcs.end());
    this->m_dispatch_funcs[fname] = func;
} //}

void ServerManager::Request(WebSocketServer* ws, int id, const std::string& fname, std::vector<std::string> args) //{
{
    if(this->m_dispatch_funcs.find(fname) == this->m_dispatch_funcs.end()) {
        this->Response(ws,                       id , true, "bad request <" + fname + ">, no handler to process this request");
        return;
    }

    this->m_dispatch_funcs[fname](this,          ws, id, fname, args);
} //}

/** [static] */
void ServerManager::NEW_INSTANCE(CLIENT_MG_DISPATCH_FUNC_ARGS) //{
{
} //}
void ServerManager::CLOSE_INSTANCE(CLIENT_MG_DISPATCH_FUNC_ARGS) //{
{
} //}
void ServerManager::GET_INSTANCES_STATUS(CLIENT_MG_DISPATCH_FUNC_ARGS) //{
{
} //}

/** [static] */
void ServerManager::GET_CONFIG_LIST(CLIENT_MG_DISPATCH_FUNC_ARGS) //{
{
} //}
void ServerManager::ADD_CONFIG(CLIENT_MG_DISPATCH_FUNC_ARGS) //{
{
} //}
void ServerManager::DELETE_CONFIG(CLIENT_MG_DISPATCH_FUNC_ARGS) //{
{
} //}
void ServerManager::RENAME_CONFIG(CLIENT_MG_DISPATCH_FUNC_ARGS) //{
{
} //}


NS_PROXY_CLIENT_END

