#include "../include/kserver_config.h"
#include "../include/utils.h"


#define DEBUG(all...) __logger->debug(all)


ServerConfig::ServerConfig() //{
{
    this->m_bind_addr = 0;
    this->m_bind_port = 1122;
} //}

bool ServerConfig::validateUser(const std::string& username, const std::string& password) //{
{
    auto u = this->m_users.find(username);
    if(u == this->m_users.end()) return false;
    if(u->second != password) return false;
    return true;
} //}

static bool get_valid_port(const json& x, uint16_t* out) //{
{
    assert(x.is_number() || x.is_string());
    uint64_t port_x;
    if(x.is_number()) {
        port_x = x.get<uint64_t>();
    } else {
        port_x = atoi(x.get<std::string>().c_str());
    }

    if(port_x > 1 << 16 || port_x == 0) return false;
    *out = port_x;
    return true;
} //}
bool ServerConfig::from_json(const json& jsonx) //{
{
    if(!jsonx.is_object()) {
        this->setError("bad config format");
        return false;
    }
    if(jsonx.find("rsa_private_key") == jsonx.end()) {
        this->setError("rsa private key not found");
        return false;
    }
    if(!jsonx["rsa_private_key"].is_string()) {
        this->setError("rsa private key bad format");
        return false;
    }
    this->m_rsa_private_key = jsonx["rsa_private_key"].get<std::string>();

    if(jsonx.find("certificate") == jsonx.end()) {
        this->setError("certificate key not found");
        return false;
    }
    if(!jsonx["certificate"].is_string()) {
        this->setError("certificate key bad format");
        return false;
    }
    this->m_cert = jsonx["certificate"].get<std::string>();

    if(jsonx.find("cipher") == jsonx.end()) {
        this->setError("cipher not found");
        return false;
    }
    if(!jsonx["cipher"].is_string()) {
        this->setError("cipher bad format");
        return false;
    }
    this->m_cipher = jsonx["cipher"].get<std::string>();

    if(jsonx.find("http_config") == jsonx.end()) {
        this->setError("http_config not found");
        return false;
    }
    if(!jsonx["http_config"].is_string()) {
        this->setError("http_config bad format");
        return false;
    }
    this->m_http_config = jsonx["http_config"].get<std::string>();

    if(jsonx.find("bind_address") == jsonx.end()) {
        this->setError("bind_address not found");
        return false;
    }
    if(!jsonx["bind_address"].is_string()) {
        this->setError("bind_address: bad format");
        return false;
    }

    uint32_t addr;
    if(str_to_ip4(jsonx["bind_address"].get<std::string>().c_str(), &addr) == false) {
        logger->error("bad ipv4 address '%s'", jsonx["bind_address"].get<std::string>().c_str());
        this->setError("bind_address: bad ipv4 address");
        return false;
    }
    this->m_bind_addr = k_ntohl(addr);
    
    if(jsonx.find("bind_port") == jsonx.end()) {
        this->setError("bind_port not found");
        return false;
    }
    if(!jsonx["bind_port"].is_string() && !jsonx["bind_port"].is_number()) {
        this->setError("bind_port: bad format");
        return false;
    }
    uint16_t port;
    if(get_valid_port(jsonx["bind_port"], &port) == false) {
        logger->error("bad port");
        this->setError("bind_port: bad format");
        return false;
    }
    this->m_bind_port = port;

    if(jsonx.find("users") == jsonx.end()) {
        logger->warn("server without any user maybe useless");
        return true;
    }

    if(!jsonx["users"].is_array()) {
        this->setError("users: bad format");
        return false;
    }

    json users = jsonx["users"];
    for(auto& i: users) {
        if(i.find("username") == i.end() ||
           i.find("password") == i.end() ||
           !i["username"].is_string() ||
           !i["password"].is_string()) {
            logger->warn("bad user account");
            continue;
        }
        this->m_users[i["username"].get<std::string>()] = i["password"].get<std::string>();
    }

    return true;
} //}
json ServerConfig::to_json() //{
{
    json res;
    res["certificate"] = this->m_cert;
    res["rsa_private_key"] = this->m_rsa_private_key;
    res["cipher"] = this->m_cipher;
    res["bind_address"] = ip4_to_str(k_htonl(this->m_bind_addr));
    res["bind_port"] = k_htons(this->m_bind_port);
    res["http_config"] = this->m_http_config;
    json users = json::array();
    for(auto& user: this->m_users) {
        json u = json::object();
        u["username"] = user.first;
        u["password"] = user.second;
        users.push_back(u);
    }
    res["users"] = users;
    return res;
} //}

ROBuf ServerConfig::toROBuf() //{
{
    auto data = this->to_json().dump(4);
    ROBuf buf(data.size() + 1);
    memcpy(buf.__base(), data.c_str(), buf.size());
    return buf;
} //}
bool  ServerConfig::fromROBuf(ROBuf buf) //{
{
    std::string str(buf.base(), buf.size());
    json jsonx;
    try {
        jsonx = json::parse(str);
    } catch (nlohmann::detail::parse_error err) {
        this->setError(err.what());
        return false;
    }

    return this->from_json(jsonx);
} //}

std::string ServerConfig::PrivateKey() {return this->m_rsa_private_key;}
std::string ServerConfig::Cert() {return this->m_cert;}
std::string ServerConfig::Cipher() {return this->m_cipher;}
std::string ServerConfig::HttpConfig() {return this->m_http_config;}

