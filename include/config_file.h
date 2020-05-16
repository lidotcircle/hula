#pragma once

#include <nlohmann/json.hpp>
#include <vector>
#include <unordered_map>

#include "robuf.h"

#include <uv.h>

using json = nlohmann::json;


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

/**                  Client Configure File JSON format                       //{
 * {
 *     "mode": "global" | "port",
 *     "rule": "all" | "match" | "nomatch",
 *     "bind_address": <valid_ipv4>,
 *     "bind_port":    <port>,
 *
 *     "servers": [
 *         {
 *             "server_name": <username>,
 *             "address": <domain name | ipv4>,
 *             "port": <port>,
 *             "certificate": <base64 encoded certificate>,
 *             "cipher": <cipher>,
 *             "username": <username>,
 *             "password": <password>
 *         }, ...
 *     ],
 *
 *     "local_users": [
 *         {
 *             "username": <username>,
 *             "password": <password>
 *         }, ...
 *     ]
 * }
 *///}


typedef std::string username_type;
typedef std::string password_type;
typedef std::string certificate_type;
typedef std::string cipher_type;

enum ConfigState {
    CONFIG_UNINIT = 0,
    CONFIG_ERROR,
    CONFIG_STALE,
    CONFIG_SYNC,
    CONFIG_AHEAD
};

enum ProxyMode {
    PROXY_MODE_GLOBAL = 0,
    PROXY_MODE_PORT
};

enum ProxyRule {
    PROXY_RULE_ALL = 0,
    PROXY_RULE_MATCH,
    PROXY_RULE_NOT_MATCH
};

class SingleServerInfo //{
{
    private:
        uint32_t m_addr;
        uint16_t m_port;
        username_type m_user;
        password_type m_pass;
        certificate_type m_cert;
        cipher_type m_cipher;

        size_t m_current_connection;

    public:
        SingleServerInfo(uint32_t addr, uint16_t port, 
                const char* name,
                const char* pass,
                const char* cert,
                const char* cipher);
}; //}
struct ClientPolicy //{
{
    ProxyMode m_mode;
    ProxyRule m_rule;
    uint16_t  m_port;
    uint32_t  m_addr;
}; //}

class ClientConfig //{
{
    public:
        using LoadCallback  = void (*)(int status, void*);
        using WriteCallback = void (*)(int status, void*);

    private:
        ConfigState                                  m_state;
        ClientPolicy                                 m_policy;
        std::vector<SingleServerInfo>                m_servers;
        std::unordered_map<std::string, std::string> m_accounts;
        std::string                                  m_filename;

        uv_loop_t* mp_loop;

        static void open_file_callback(uv_fs_t* req);

    public:
        bool validateUser(const std::string& username, const std::string& password);

        int  loadFromFile(LoadCallback, void*);
        int  writeToFile (WriteCallback, void*);

        ClientConfig(const char* filename);

        ClientConfig() = delete;
        ClientConfig(const ClientConfig&) = delete;
        ClientConfig(ClientConfig&&) = delete;
        ClientConfig& operator=(const ClientConfig&) = delete;
        ClientConfig& operator=(ClientConfig&&) = delete;
}; //}

class ServerConfig //{
{
    public:
        using LoadCallback  = void (*)(int status, void*);
        using WriteCallback = void (*)(int status, void*);

    private:
        std::string m_rsa_private_key;
        std::string m_cipher;

        std::unordered_map<std::string, std::string> m_users;

    public:
        ServerConfig(const char* private_key, const char* cipher, std::unordered_map<std::string, std::string> users);

        ServerConfig() = delete;
        ServerConfig(const ServerConfig&) = delete;
        ServerConfig(ServerConfig&&) = delete;
        ServerConfig& operator=(const ServerConfig&) = delete;
        ServerConfig& operator=(ServerConfig&&) = delete;

        int loadFromFile(LoadCallback);
        int writeToFile (WriteCallback);
}; //}

