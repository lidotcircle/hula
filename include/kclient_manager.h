#pragma once

#include "k_manager.hpp"
#include "kclient_server.h"
#include "kclient.h"


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


class ServerManager: public KManager<Server> 
{

    private:
#define FUNC_CALL(fname) static void fname(RequestArg arg);
        CLIENT_RPC_LIST(FUNC_CALL)
#undef  FUNC_CALL

    public:
        ServerManager();
        void start() override;
};


NS_PROXY_CLIENT_END


