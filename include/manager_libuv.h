#pragma once

#include "manager.h"
#include "stream_libuv.h"
#include "file_libuv.h"


class ResourceManagerUV: virtual public ResourceManager 
{
    protected:
        HttpFileServer*  createHttpFileServer(const std::string& filename, UNST con) override;
        WebSocketServer* createWSSession(UNST con) override;
};

