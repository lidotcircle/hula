#pragma once

#include "file.h"
#include "file_libuv.h"
#include "config_file.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

//                              HttpFileServerConfig JSON format                  //{
/**
 * {
 *     "document_root": <dir>, 
 *     "bind_port": <port>, 
 *     "bind_address": <address>
 * }
 */
//}


class HttpFileServerConfig: public ConfigFile {
    private:
        std::string m_docroot;
        uint32_t    m_bind_addr;
        uint16_t    m_bind_port;

    protected:
        bool  fromROBuf(ROBuf buf) override;
        ROBuf toROBuf() override;

        bool from_json(const json&);
        json to_json();

    public:
        HttpFileServerConfig();

        HttpFileServerConfig(const HttpFileServerConfig&) = delete;
        HttpFileServerConfig(HttpFileServerConfig&&) = delete;
        HttpFileServerConfig& operator=(const HttpFileServerConfig&) = delete;
        HttpFileServerConfig& operator=(HttpFileServerConfig&&) = delete;

        const std::string& DocRoot();
        uint32_t BindAddr();
        uint16_t BindPort();
};


class UVHttpFileServerConfig: public HttpFileServerConfig, public UVFile {
    public:
    inline UVHttpFileServerConfig(uv_loop_t* loop, const std::string& filename): HttpFileServerConfig(), UVFile(loop, filename) {}
};

