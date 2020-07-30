#pragma once

#include "manager.h"
#include "kclient_server.h"
#include "ifbs.h"

#include <set>
#include <map>
#include <filesystem>
#include <fstream>
#include <memory>


#define DEBUG(all...) __logger->debug(all)
#define CONF_FILE_EXTENSION ".json"

template<typename T>
class KManager: virtual public ResourceManager
{
    private:
        class __RequestArg {
            public:
                virtual void fail(const std::string& reason)    = 0;
                virtual void success(const std::string& result) = 0;
                virtual KManager* GetThis() = 0;
                virtual int  GetID() = 0;
                virtual const std::string& GetFunc() = 0;
                virtual size_t  GetArgc() = 0;
                virtual IFBS GetArg(size_t i) = 0;
                inline virtual ~__RequestArg() {}
        };
    public:
        using RequestArg = std::shared_ptr<__RequestArg>;
        using Server     = T;
        using ServerId   = uint8_t;
        using ConfigId   = uint8_t;

        static bool verify_args(RequestArg arg, const std::string& as);

    private:
        using DispatchFunc = void (*)(RequestArg);
        std::map<std::string, DispatchFunc> m_dispatch_funcs;

        ServerId m_servers_inc;
        ConfigId m_configs_inc;
        std::string m_default_config_dir;
        std::string m_default_config_file;
        std::map<ServerId, std::pair<ConfigId, Server*>> m_servers;
        std::map<ConfigId, std::string>   m_configs;
        std::map<ConfigId, std::set<ServerId>> m_config_server;

        class RequestArgImpl: public __RequestArg  //{
        {
            private:
                std::string m_fname;
                int         m_id;
                WebSocketServer* m_ws;
                std::vector<std::string> m_args;
                KManager<Server>* m_manager;
                bool m_returned;

            public:
                inline RequestArgImpl(const std::string& fname, int id, WebSocketServer* ws, //{
                               std::vector<std::string>&& args, KManager<Server>* manager): m_args(std::move(args))
                {
                    this->m_fname = fname;
                    this->m_id = id;
                    this->m_ws = ws;
                    this->m_manager = manager;
                    this->m_returned = false;
                } //}
                inline void fail(const std::string& reason) override {
                    assert(this->m_returned == false);
                    this->m_returned = true;
                    this->m_manager->Response(this->m_ws, this->m_id, true, reason);
                }
                void success(const std::string& result) override {
                    assert(this->m_returned == false);
                    this->m_returned = true;
                    this->m_manager->Response(this->m_ws, this->m_id, false, result);
                }
                inline KManager* GetThis() {return this->m_manager;}
                inline int  GetID() override {return this->m_id;}
                inline const std::string& GetFunc() override {return this->m_fname;}
                inline size_t  GetArgc() override {return this->m_args.size();}
                inline IFBS    GetArg(size_t i) override {assert(i < this->GetArgc()); return this->m_args[i];}
                inline ~RequestArgImpl() {assert(this->m_returned == true);} // TODO ???
        }; //}

        using ResourceManager::bind;
        using ResourceManager::listen;


    protected:
        virtual Server* createServer(const std::string& filename, UNST con) = 0;

        void register_dispatch(const std::string& fname, DispatchFunc);

        int  new_server(ServerId config_id);
        void shutdown_server(ServerId server_id);
        bool has_server(ServerId server_id);

        void rescan_configs();
        bool add_config   (const std::string& filename, const std::string& config);
        bool delete_config(ConfigId config_id);
        bool rename_config(ConfigId config_id, const std::string& newname);
        bool has_config(ConfigId config_id);

        void Request(WebSocketServer* ws, int id, const std::string& fname, std::vector<std::string> args) override;


    public:
        KManager(const std::string& default_config_dir, const std::string& default_config_file);

        KManager(KManager&&) = delete;
        KManager(const KManager&) = delete;
        KManager& operator=(KManager&&) = delete;
        KManager& operator=(const KManager&) = delete;

        virtual void start();
        void close() override;

        ~KManager();
};


template<typename T>
KManager<T>::KManager(const std::string& default_config_dir, const std::string& default_config_file): //{
    m_dispatch_funcs(), m_servers(), m_config_server()
{
    DEBUG("call %s", FUNCNAME);
    this->m_default_config_dir = default_config_dir;
    this->m_default_config_file = default_config_file;
    this->m_servers_inc = 1;
    this->m_configs_inc = 1;
} //}

template<typename T>
void KManager<T>::start() //{
{
    DEBUG("call %s", FUNCNAME);

    this->bind();
    this->listen();

    this->rescan_configs();
    assert(this->m_configs.size() > 0);
    this->new_server(this->m_configs.begin()->first);
} //}

template<typename T>
int KManager<T>::new_server(ServerId config_id) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_configs.find(config_id) != this->m_configs.end());
    auto filename = this->m_configs[config_id];
    auto s = this->createServer(filename, this->NewUNST());

    s->trylisten();

    auto id = this->m_servers_inc++;
    this->m_servers[id] = std::make_pair(config_id, s);

    if(this->m_config_server.find(config_id) == this->m_config_server.end())
        this->m_config_server[config_id] = std::set<ServerId>();
    this->m_config_server[config_id].insert(id);

    return id;
} //}
template<typename T>
void KManager<T>::shutdown_server(ServerId server_id) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_servers.find(server_id) != this->m_servers.end());
    auto cc = this->m_servers[server_id];
    this->m_servers.erase(this->m_servers.find(server_id));
    assert(this->m_config_server.find(cc.first) != this->m_config_server.end());
    assert(this->m_config_server[cc.first].find(server_id) != this->m_config_server[cc.first].end());
    this->m_config_server[cc.first].erase(this->m_config_server[cc.first].find(server_id));

    cc.second->close();
    delete cc.second;
} //}
template<typename T>
bool KManager<T>::has_server(ServerId server_id) //{
{
    DEBUG("call %s", FUNCNAME);
    return this->m_servers.find(server_id) != this->m_servers.end();
} //}

template<typename T>
void KManager<T>::rescan_configs() //{
{
    DEBUG("call %s", FUNCNAME);
    std::filesystem::path config_dir = this->m_default_config_dir;
    if(!std::filesystem::is_directory(config_dir))
        return;

    std::vector<std::filesystem::path> files;
    std::filesystem::directory_iterator diter(config_dir, std::filesystem::directory_options::skip_permission_denied);
    for(;diter != std::filesystem::end(diter); diter++) {
        auto ff = *diter;
        if(ff.is_regular_file() && ff.path().extension() == CONF_FILE_EXTENSION)
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
template<typename T>
bool KManager<T>::add_config(const std::string& filename, const std::string& config) //{
{
    DEBUG("call %s", FUNCNAME);
    auto id = this->m_configs_inc++;

    std::filesystem::path p = this->m_default_config_dir;
    p.append(filename);
    assert(p.extension() == CONF_FILE_EXTENSION);

    if(std::filesystem::exists(p))
        return false;

    std::fstream file(p, std::ios_base::out);
    if(!file.is_open())
        return false;

    file << config << std::endl;
    this->m_configs[id] = p;
    return true;
} //}
template<typename T>
bool KManager<T>::delete_config  (ConfigId config_id) //{
{
    DEBUG("call %s", FUNCNAME);
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
template<typename T>
bool KManager<T>::rename_config(ConfigId config_id, const std::string& newname) //{
{
    DEBUG("call %s", FUNCNAME);
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
template<typename T>
bool KManager<T>::has_config(ConfigId config_id) //{
{
    DEBUG("call %s", FUNCNAME);
    return this->m_configs.find(config_id) != this->m_configs.end();
} //}

template<typename T>
void KManager<T>::register_dispatch(const std::string& fname, DispatchFunc func) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_dispatch_funcs.find(fname) == this->m_dispatch_funcs.end());
    this->m_dispatch_funcs[fname] = func;
} //}

template<typename T>
void KManager<T>::Request(WebSocketServer* ws, int id, const std::string& fname, std::vector<std::string> args) //{
{
    DEBUG("call %s", FUNCNAME);
    if(this->m_dispatch_funcs.find(fname) == this->m_dispatch_funcs.end()) {
        this->Response(ws, id , true, "bad request <" + fname + ">, no handler to process this request");
        return;
    }

    RequestArgImpl* _arg = new RequestArgImpl(fname, id, ws, std::move(args), this);
    this->m_dispatch_funcs[fname](RequestArg(_arg));
} //}

template<typename T>
void KManager<T>::close() //{
{
    DEBUG("call %s", FUNCNAME);
    std::vector<ServerId> s_ids;
    for(auto& s: this->m_servers)
        s_ids.push_back(s.first);
    for(auto& id: s_ids)
        this->shutdown_server(id);

    this->ResourceManager::close();
} //}

template<typename T>
KManager<T>::~KManager() {}

template<typename T>
bool KManager<T>::verify_args(RequestArg arg, const std::string& as) //{
{
    DEBUG("call %s", FUNCNAME);
    if(arg->GetArgc() != as.size()) return false;
    for(size_t i=0;i<as.size();i++) {
        char c = as[i];
        auto a = arg->GetArg(i);
        switch(c) {
            case 'i':
                if(!a.is_integer()) return false;
                break;
            case 'f':
                if(!a.is_float()) return false;
                break;
            case 'b':
                if(!a.is_boolean()) return false;
                break;
            case 's':
                break;
            default:
                return false;
        }
    }
    return true;
} //}

