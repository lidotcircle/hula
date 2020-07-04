#pragma once

#include <nlohmann/json.hpp>
#include <vector>
#include <unordered_map>

#include "config_file.h"
#include "file_libuv.h"

using nlohmann::json;


/**                  Server Configure File JSON format                       //{
 * {
 *     "rsa_private_key": <key>,
 *     "cipher": <cipher>,
 *     "users": [
 *         {
 *             "username": <username>,
 *             "password": <password>
 *         }, ...
 *     ]
 * }
 *///}


class ServerConfig: public ConfigFile //{
{
    private:
        std::string m_rsa_private_key;
        std::string m_cipher;

        std::unordered_map<std::string, std::string> m_users;

        uint32_t m_bind_addr;
        uint16_t m_bind_port;

        json to_json();
        bool from_json(const json&);

        ROBuf toROBuf() override;
        bool  fromROBuf(ROBuf buf) override;


    public:
        ServerConfig();

        bool validateUser(const std::string& username, const std::string& password);

        ServerConfig(const ServerConfig&) = delete;
        ServerConfig(ServerConfig&&) = delete;
        ServerConfig& operator=(const ServerConfig&) = delete;
        ServerConfig& operator=(ServerConfig&&) = delete;

        std::string RSA();
        std::string Cipher();

        inline uint32_t BindAddr() {return this->m_bind_addr;}
        inline uint32_t BindPort() {return this->m_bind_port;}
}; //}


class UVServerConfig: public ServerConfig, public UVFile {
    public:
    inline UVServerConfig(uv_loop_t* loop, const std::string& filename): ServerConfig(), UVFile(loop, filename) {}
};

