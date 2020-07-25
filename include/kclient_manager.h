#pragma once

#include "manager.h"
#include "kclient_server.h"

#include <set>
#include <map>


/** RPC LIST */
/**
 * @NEW_INSTANCE            <=        (CONFIG_ID: int)                    =>            (INSTANCE_ID)
 * @CLOSE_INSTANCE          <=        (INSTANCE_ID: int)                  =>            ()
 * @GET_INSTANCES_STATUS    <=        ()                                  =>            (INSTANCE_STATUS[])
 *
 * @GET_CONFIG_LIST         <=        ()                                  =>            (CONFIG[])
 * @ADD_CONFIG              <=        (CONFIG_NAME: string)               =>            (CONFIG_ID)
 * @DELETE_CONFIG           <=        (CONFIG_ID: int)                    =>            ()
 * @RENAME_CONFIG           <=        (CONFIG_ID: int, NEWNAME: string)   =>            ()
 */

#define CLIENT_RPC_LIST(XX) \
    XX(NEW_INSTANCE) \
    XX(CLOSE_INSTANCE) \
    XX(GET_INSTANCES_STATUS) \
    \
    XX(GET_CONFIG_LIST) \
    XX(ADD_CONFIG) \
    XX(DELETE_CONFIG) \
    XX(RENAME_CONFIG) \


NS_PROXY_CLIENT_START


#define CLIENT_MG_DISPATCH_FUNC_ARGS \
     ServerManager* mg, WebSocketServer* ws, int id, \
     const std::string& fname, std::vector<std::string> args

class ServerManager: virtual public ResourceManager
{
    private:
        using DispatchFunc = void (*)(CLIENT_MG_DISPATCH_FUNC_ARGS);
        std::map<std::string, DispatchFunc> m_dispatch_funcs;

        int m_servers_inc;
        int m_configs_inc;
        std::map<int, std::pair<int, Server*>> m_servers;
        std::map<int, std::string>   m_configs;
        std::map<int, std::set<int>> m_config_server;

        void register_dispatch(const std::string& fname, DispatchFunc);

#define DEFINE_FUNC(fname) static void fname(CLIENT_MG_DISPATCH_FUNC_ARGS);
        CLIENT_RPC_LIST(DEFINE_FUNC);
#undef DEFINE_FUNC

        int  new_server(int config_id);
        void shutdown_server(int server_id);

        void rescan_configs();
        bool add_config   (const std::string& filename, const std::string& config);
        bool delete_config(int config_id);
        bool rename_config(int config_id, const std::string& newname);


    protected:
        void Request(WebSocketServer* ws, int id, const std::string& fname, std::vector<std::string> args) override;

        virtual Server* createServer(const std::string& filename, UNST con) = 0;


    public:
        ServerManager();

        ServerManager(ServerManager&&) = delete;
        ServerManager(const ServerManager&) = delete;
        ServerManager& operator=(ServerManager&&) = delete;
        ServerManager& operator=(const ServerManager&) = delete;

        void start();

        ~ServerManager();
};


NS_PROXY_CLIENT_END

