#pragma once

#include "file.h"
#include "file_libuv.h"
#include "config_file.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

//                              HttpFileServerConfig JSON format                  //{
/**
 * {
 *     "document_root": <dir>
 * }
 */
//}


class HttpFileServerConfig: public ConfigFile {
    private:
        std::string m_docroot;

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
};


class UVHttpFileServerConfig: public HttpFileServerConfig, public UVFile {
    public:
    inline UVHttpFileServerConfig(uv_loop_t* loop, const std::string& filename): HttpFileServerConfig(), UVFile(loop, filename) {}
};

