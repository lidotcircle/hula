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
 *     "socks5_auth": "allowed" | "password",
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

enum Socks5AuthMethod {
    SOCKS5_NO_REQUIRED,
    SOCKS5_PASSWORD
};

class SingleServerInfo //{
{
    private:
        uint16_t m_port;
        std::string   m_addr;
        username_type m_user;
        password_type m_pass;
        certificate_type m_cert;
        cipher_type m_cipher;

        std::string   m_server_name;

        size_t m_current_connection = 0;

    public:
        SingleServerInfo(const std::string& addr, uint16_t port, 
                const std::string& server_name,
                const std::string& name,
                const std::string& pass,
                const std::string& cert,
                const std::string& cipher);

        inline void increase() {this->m_current_connection++;}
        inline void decrease() {this->m_current_connection--;}

        inline void new_port(uint16_t port){this->m_port = port;}
        inline void new_addr(const std::string& addr){this->m_addr = addr;}
        inline void new_user(const std::string& user){this->m_user = user;}
        inline void new_pass(const std::string& pass){this->m_pass = pass;}
        inline void new_cert(const std::string& cert){this->m_cert = cert;}
        inline void new_cipher(const std::string& cipher){this->m_cipher = cipher;}
        inline void new_name(const std::string& name){this->m_server_name = name;}

        inline uint16_t Port(){return this->m_port;}
        inline const std::string& new_addr(){return this->m_addr;}
        inline const std::string& new_user(){return this->m_user;}
        inline const std::string& new_pass(){return this->m_pass;}
        inline const std::string& new_cert(){return this->m_cert;}
        inline const std::string& new_cipher(){return this->m_cipher;}
        inline const std::string& new_name(){return this->m_server_name;}

        json to_json();
}; //}
struct ClientPolicy //{
{
    ProxyMode m_mode;
    ProxyRule m_rule;
    Socks5AuthMethod m_method;
    uint16_t  m_port;
    uint32_t  m_addr;
}; //}

class ClientConfig //{
{
    public:
        /** status greater than 0 mean error, errno */
        using LoadCallback  = void (*)(int error, void*);
        using WriteCallback = void (*)(int error, void*);

    private:
        ConfigState                                  m_state;
        ClientPolicy                                 m_policy;
        std::vector<SingleServerInfo>                m_servers;
        std::unordered_map<std::string, std::string> m_accounts;
        std::string                                  m_filename;

        std::string m_error;

        uv_loop_t* mp_loop;

        static void open_file_callback(uv_fs_t* req);
        static void stat_file_callback(uv_fs_t* req);
        static void read_file_callback(uv_fs_t* req);
        static void close_file_callback(uv_fs_t* req);

        static void open_file_callback2(uv_fs_t* req);
        static void write_file_callback(uv_fs_t* req);

        int from_json(const json&);
        int set_policy(const json&);
        int set_servers(const json&);
        int set_users(const json&);

        json to_json();
        json servers_to_json();
        json users_to_json();

    public:
        bool validateUser(const std::string& username, const std::string& password);

        int  loadFromFile(LoadCallback, void*);
        int  writeToFile (WriteCallback, void*);

        ClientConfig(uv_loop_t* loop, const char* filename);

        ClientConfig() = delete;
        ClientConfig(const ClientConfig&) = delete;
        ClientConfig(ClientConfig&&) = delete;
        ClientConfig& operator=(const ClientConfig&) = delete;
        ClientConfig& operator=(ClientConfig&&) = delete;

        inline json toJson() {return this->to_json();}

        inline std::string getError() {return this->m_error;}

        inline std::vector<SingleServerInfo>& Servers() {return this->m_servers;}
        inline std::unordered_map<std::string, std::string>& Users() {return this->m_accounts;}

        inline void new_file(const std::string& filename) {this->m_filename = filename;}

        inline uint32_t BindAddr() {return this->m_policy.m_addr;}
        inline uint32_t BindPort() {return this->m_policy.m_port;}

        inline ClientPolicy Policy() {return this->m_policy;}
}; //}

class ServerConfig //{
{
    public:
        using LoadCallback  = void (*)(int status, void*);

    private:
        std::string m_rsa_private_key;
        std::string m_cipher;

        std::unordered_map<std::string, std::string> m_users;

        uv_loop_t*  mp_loop;
        std::string m_filename;
        std::string m_error;
        ConfigState m_state;

        uint32_t m_bind_addr;
        uint16_t m_bind_port;

        int from_json(const json&);

        static void read_file_callback(uv_fs_t* req);

    public:
        ServerConfig(uv_loop_t* loop, const std::string& filename);

        bool validateUser(const std::string& username, const std::string& password);

        ServerConfig() = delete;
        ServerConfig(const ServerConfig&) = delete;
        ServerConfig(ServerConfig&&) = delete;
        ServerConfig& operator=(const ServerConfig&) = delete;
        ServerConfig& operator=(ServerConfig&&) = delete;

        int loadFromFile(LoadCallback, void*);

        std::string RSA();
        std::string Cipher();

        inline uint32_t BindAddr() {return this->m_bind_addr;}
        inline uint32_t BindPort() {return this->m_bind_port;}
}; //}

