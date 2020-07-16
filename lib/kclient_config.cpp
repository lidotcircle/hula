#include "../include/kclient_config.h"
#include "../include/config.h"
#include "../include/utils.h"


#define DEBUG(all...) __logger->debug(all)


//                      class SingleServerInfo             //{
SingleServerInfo::SingleServerInfo(const std::string& addr,    uint16_t port, const std::string& server_name,
                                   const std::string& name, const std::string& pass,
                                   const std::string& cert, const std::string& cipher) //{
{
    this->m_addr = addr;
    this->m_port = port;

    this->m_server_name = server_name;

    this->m_user = name;
    this->m_pass = pass;
    this->m_cert = cert;
    this->m_cipher = cipher;
} //}

json SingleServerInfo::to_json() //{
{
    json result = json::object();
    result["server_name"] = this->m_server_name;
    result["address"] = this->m_addr;
    result["port"]    = this->m_port; // FIXME ??
    result["certificate"] = this->m_cert;
    result["cipher"] = this->m_cipher;
    result["username"] = this->m_user;
    result["password"] = this->m_pass;
    return result;
} //}

//}


ClientConfig::ClientConfig(): m_policy(), m_servers(), m_accounts(), mp_proxyrule(nullptr), mp_adblock_rule(nullptr) {}

bool ClientConfig::validateUser(const std::string& username, const std::string& password) //{
{
    auto u = this->m_accounts.find(username);
    if(u == this->m_accounts.end()) return false;
    if(u->second != password) return false;
    return true;
} //}

bool ClientConfig::fromROBuf(ROBuf buf) //{
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
ROBuf ClientConfig::toROBuf() //{
{
    std::string data = this->to_json().dump(4);
    ROBuf buf(data.size() + 1);
    memcpy(buf.__base(), data.c_str(), buf.size());
    return buf;
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
bool ClientConfig::set_policy(const json& jsonx) //{
{
    if(jsonx.find("mode") == jsonx.end() || 
       jsonx.find("rule") == jsonx.end() || 
       jsonx.find("bind_address") == jsonx.end() || 
       jsonx.find("bind_port") == jsonx.end() || 
       jsonx.find("proxy_rule") == jsonx.end() || 
       jsonx.find("socks5_authentication") == jsonx.end()) {
        this->setError("policy fields don't match required");
        return false;
    }

    auto mode = jsonx["mode"];
    auto rule = jsonx["rule"];
    auto bind_address = jsonx["bind_address"];
    auto bind_port = jsonx["bind_port"];
    auto method = jsonx["socks5_authentication"];
    auto proxyrule = jsonx["proxy_rule"];
    if(!mode.is_string()) {
        this->setError("invalid proxy mode");
        return false;
    }
    if(!rule.is_string()) {
        this->setError("invalid proxy rule");
        return false;
    }
    if(!method.is_string()) {
        this->setError("invalid method");
        return false;
    }
    if(!bind_address.is_string()) {
        this->setError("invalid bind_address");
        return false;
    }
    if(!bind_port.is_string() && !bind_port.is_number()) {
        this->setError("invalid bind_port");
        return false;
    }
    if(!proxyrule.is_string()) {
        this->setError("proxy_rule: invalid filename");
        return false;
    } else {
        this->m_policy.m_proxyrule_filename = proxyrule.get<std::string>();
    }
    if(jsonx.find("ad_rule") != jsonx.end()) {
        auto ad_rule = jsonx["ad_rule"];
        if(ad_rule.is_string()) this->m_policy.m_adrule_filename = ad_rule;
    }

    if(mode.get<std::string>() == "global") {
        this->m_policy.m_mode = PROXY_MODE_GLOBAL;
    } else if(mode.get<std::string>() == "port") {
        this->m_policy.m_mode = PROXY_MODE_PORT;
    } else {
        this->setError("incorrect proxy mode");
        return false;
    }

    if(rule.get<std::string>() == "all") {
        this->m_policy.m_rule = PROXY_RULE_ALL;
    } else if(rule.get<std::string>() == "match") {
        this->m_policy.m_rule = PROXY_RULE_MATCH;
    } else if(rule.get<std::string>() == "nomatch") {
        this->m_policy.m_rule = PROXY_RULE_NOT_MATCH;
    } else {
        this->setError("incorrect proxy rule");
        return false;
    }

    if(method.get<std::string>() == "allowed") {
        this->m_policy.m_method = SOCKS5_NO_REQUIRED;
    } else if(method.get<std::string>() == "password") {
        this->m_policy.m_method = SOCKS5_PASSWORD;
    } else {
        this->setError("incorrect authentication method");
        return false;
    }

    uint32_t ipv4;
    if(str_to_ip4(bind_address.get<std::string>().c_str(), &ipv4) == false) {
        this->setError("invalid bind_address, bad format");
        return false;
    }
    this->m_policy.m_addr = k_ntohl(ipv4);

    uint16_t port_x;
    if(!get_valid_port(bind_port, &port_x)) {
        this->setError("invalid bind_port, bad format");
        return false;
    }
    this->m_policy.m_port = port_x;
    return true;
} //}
bool ClientConfig::set_servers(const json& jsonx) //{
{
    this->m_servers.clear();
    if(jsonx.find("servers") == jsonx.end()) {
        this->setError("JSON: servers field doesn't exists");
        return false;
    }

    if(!jsonx["servers"].is_array()) {
        this->setError("JSON: bad config format at 'servers'");
        return false;
    }

    json m = jsonx["servers"];
    for(auto j = m.begin(); j != m.end(); j++) {
        if(!j->is_object()) {
            this->setError("JSON: bad json format, members of [servers] are an object");
            continue;
        }
        if(!j->at("server_name").is_string() ||
           !j->at("address").is_string() ||
           (!j->at("port").is_string() && !j->at("port").is_number()) ||
           !j->at("certificate").is_string() ||
           !j->at("cipher").is_string() ||
           !j->at("username").is_string() ||
           !j->at("password").is_string()
          ) {
            this->setError("JSON: required fields doesn't exists in [servers] object");
            continue;
        }
        uint16_t port;
        if(!get_valid_port(j->at("port"), &port)) {
            this->setError("JSON: a bad port");
            return -1;
        }
        auto server_name = j->at("server_name").get<std::string>();
        auto address     = j->at("address").get<std::string>();
        auto certificate = j->at("certificate").get<std::string>();
        auto cipher      = j->at("cipher").get<std::string>();
        auto username    = j->at("username").get<std::string>();
        auto password    = j->at("password").get<std::string>();

        this->m_servers.push_back(
                SingleServerInfo(address, port, 
                                 server_name, username, 
                                 password, certificate, cipher));
    }
    return true;
} //}
bool ClientConfig::set_users(const json& jsonx) //{
{
    this->m_accounts.clear();
    if(jsonx.find("local_users") == jsonx.end())
        return true;

    if(!jsonx["local_users"].is_array()) {
        this->setError("JSON: bad format in 'local_users'");
        return false;
    }


    json m = jsonx["local_users"];
    for(auto j = m.begin(); j != m.end(); j++) {
        if(!j->is_object()) {
            this->setError("JSON: members of [local_users] should be object");
            continue;
        }
        if(!j->at("username").is_string() ||
           !j->at("password").is_string()
          ) {
            this->setError("JSON: [username] and [password] field should be string type");
            continue;
        }
        auto username    = j->at("username").get<std::string>();
        auto password    = j->at("password").get<std::string>();

        if(this->m_accounts.find(username) != this->m_accounts.end()) {
            this->setError("JSON: duplicated [username]");
            continue;
        }
        this->m_accounts[username] = password;
    }
    return true;
} //}

struct __clientconfig_state: public CallbackPointer {
    ClientConfig* _this;
    inline __clientconfig_state(decltype(_this)_this): _this(_this) {}
};
bool ClientConfig::from_json(const json& jsonx) //{
{
    DEBUG("call ClientConfig::from_json()");
    if(!this->set_policy(jsonx))
        return false;
    if(!this->set_servers(jsonx))
        return false;
    if(!this->set_users(jsonx))
        return false;

    if(this->mp_proxyrule != nullptr) delete this->mp_proxyrule;
    this->mp_proxyrule = this->createProxyConfig(this->m_policy.m_proxyrule_filename);
    auto ptr = new __clientconfig_state(this);
    this->add_callback(ptr);
    this->mp_proxyrule->loadFromFile(load_proxyrule_callback, ptr);

    if(this->m_policy.m_adrule_filename.size() > 0) {
        if(this->mp_adblock_rule != nullptr) delete this->mp_adblock_rule;
        this->mp_adblock_rule = this->createProxyConfig(this->m_policy.m_adrule_filename);
        auto ptr = new __clientconfig_state(this);
        this->add_callback(ptr);
        this->mp_adblock_rule->loadFromFile(load_adrule_callback, ptr);
    }

    return true;
} //}
/** [static] */
void ClientConfig::load_proxyrule_callback(int status, void* data) //{
{
    __clientconfig_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0) {
        assert(false);
        _this->setError("load proxy rule fail");
    }
} //}
/** [static] */
void ClientConfig::load_adrule_callback(int status, void* data) //{
{
    __clientconfig_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0) {
        assert(false);
        _this->setError("load ad rule fail");
    }
} //}

bool ClientConfig::ProxyMatch(const std::string& addr, int port) //{
{
    if(this->mp_proxyrule == nullptr) return false;
    return this->mp_proxyrule->match(addr, port);
} //}
bool ClientConfig::AdMatch(const std::string& addr, int port) //{
{
    if(this->mp_adblock_rule == nullptr) return false;
    return this->mp_adblock_rule->match(addr, port);
} //}

json ClientConfig::to_json() //{
{
    json result = json::object();
    switch(this->m_policy.m_mode) {
        case PROXY_MODE_GLOBAL: 
            result["mode"] = "global";
            break;
        case PROXY_MODE_PORT:
            result["mode"] = "port";
            break;
    }
    switch(this->m_policy.m_rule) {
        case PROXY_RULE_ALL:
            result["rule"] = "all";
            break;
        case PROXY_RULE_MATCH:
            result["rule"] = "match";
            break;
        case PROXY_RULE_NOT_MATCH:
            result["rule"] = "nomatch";
            break;
    }
    result["bind_address"] = std::string(ip4_to_str(k_htonl(this->m_policy.m_addr)));
    result["bind_port"]    = this->m_policy.m_port;

    result["servers"] = this->servers_to_json();
    result["local_users"]   = this->users_to_json();
    return result;
} //}
json ClientConfig::servers_to_json() //{
{
    json result = json::array();
    for(auto& i: this->m_servers) 
        result.push_back(i.to_json());
    return result;
} //}
json ClientConfig::users_to_json() //{
{
    json result = json::array();
    for(auto& i: this->m_accounts) {
        json user = json::object();
        user["username"] = i.first;
        user["password"] = i.second;
        result.push_back(user);
    }

    return result;
} //}

ClientConfig::~ClientConfig() //{
{
    if(this->mp_proxyrule != nullptr) delete this->mp_proxyrule;
    if(this->mp_adblock_rule != nullptr) delete this->mp_adblock_rule;
} //}

