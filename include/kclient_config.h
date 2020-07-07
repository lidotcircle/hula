#pragma once

#include <nlohmann/json.hpp>
#include <vector>
#include <unordered_map>

#include "config_file.h"
#include "file_libuv.h"
#include "proxy_config.h"

using nlohmann::json;


/**                  Client Configure File JSON format                       //{
 * {
 *     "mode": "global" | "port",
 *     "rule": "all" | "match" | "nomatch",
 *     "socks5_auth": "allowed" | "password",
 *     "bind_address": <valid_ipv4>,
 *     "bind_port":    <port>,
 *     "proxy_rule": <filename>,
 *     "ad_rule": <filename>, // optional
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

        inline void new_addr(const std::string& addr){this->m_addr = addr;}
        inline void new_port(uint16_t port){this->m_port = port;}
        inline void new_user(const std::string& user){this->m_user = user;}
        inline void new_pass(const std::string& pass){this->m_pass = pass;}
        inline void new_cert(const std::string& cert){this->m_cert = cert;}
        inline void new_cipher(const std::string& cipher){this->m_cipher = cipher;}
        inline void new_name(const std::string& name){this->m_server_name = name;}

        inline const std::string& addr(){return this->m_addr;}
        inline uint16_t           port(){return this->m_port;}
        inline const std::string& user(){return this->m_user;}
        inline const std::string& pass(){return this->m_pass;}
        inline const std::string& cert(){return this->m_cert;}
        inline const std::string& cipher(){return this->m_cipher;}
        inline const std::string& name(){return this->m_server_name;}

        json to_json();
}; //}
struct ClientPolicy //{
{
    ProxyMode m_mode;
    ProxyRule m_rule;
    uint16_t  m_port;
    uint32_t  m_addr;

    Socks5AuthMethod m_method;
    std::string      m_proxyrule_filename;
    std::string      m_adrule_filename;
    inline ClientPolicy(): m_mode(PROXY_MODE_PORT), m_rule(PROXY_RULE_ALL), 
                           m_addr(0), m_port(1080), 
                           m_method(Socks5AuthMethod::SOCKS5_NO_REQUIRED),
                           m_proxyrule_filename(), m_adrule_filename() {}
}; //}


class ClientConfig: public ConfigFile //{
{
    private:
        ClientPolicy                                 m_policy;
        std::vector<SingleServerInfo>                m_servers;
        std::unordered_map<std::string, std::string> m_accounts;
        ProxyConfig* mp_proxyrule;
        ProxyConfig* mp_adblock_rule;

        bool  fromROBuf(ROBuf buf) override;
        ROBuf toROBuf() override;

        bool from_json(const json&);
        bool set_policy(const json&);
        bool set_servers(const json&);
        bool set_users(const json&);

        json to_json();
        json servers_to_json();
        json users_to_json();


    protected:
        virtual ProxyConfig* createProxyConfig(const std::string& filename) = 0;
        static void load_proxyrule_callback(int status, void* data);
        static void load_adrule_callback(int status, void* data);


    public:
        ClientConfig();

        ClientConfig(const ClientConfig&) = delete;
        ClientConfig(ClientConfig&&) = delete;
        ClientConfig& operator=(const ClientConfig&) = delete;
        ClientConfig& operator=(ClientConfig&&) = delete;

        bool validateUser(const std::string& username, const std::string& password);

        inline auto& Servers() {return this->m_servers;}
        inline auto& Users()   {return this->m_accounts;}
        inline auto& Policy()  {return this->m_policy;}

        inline auto BindAddr() {return this->m_policy.m_addr;}
        inline auto BindPort() {return this->m_policy.m_port;}

        bool ProxyMatch(const std::string& addr, int port);
        bool AdMatch   (const std::string& addr, int port);

        ~ClientConfig();
}; //}


class UVClientConfig: public ClientConfig, public UVFile {
    public:
    inline UVClientConfig(uv_loop_t* loop, const std::string& filename): ClientConfig(), UVFile(loop, filename) {}
    inline ProxyConfig* createProxyConfig(const std::string& filename) override {return new UVProxyConfig(this->get_uv_loop(), filename);}
};

