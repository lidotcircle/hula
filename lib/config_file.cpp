#include "../include/config_file.h"
#include "../include/utils.h"

#include <assert.h>

#include <uv.h>

#include <exception>


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


//                 class ClientConfig                      //{
ClientConfig::ClientConfig(uv_loop_t* loop, const char* filename) //{
{
    this->mp_loop = loop;
    this->m_state = CONFIG_UNINIT;
    this->m_filename = std::string(filename);

    this->m_policy.m_rule = PROXY_RULE_ALL;
    this->m_policy.m_mode = PROXY_MODE_PORT;
    this->m_policy.m_addr = 0;
    this->m_policy.m_port = 1080;
} //}

bool ClientConfig::validateUser(const std::string& username, const std::string& password) //{
{
    assert(this->m_state > CONFIG_ERROR);

    auto u = this->m_accounts.find(username);
    if(u == this->m_accounts.end()) return false;
    if(u->second != password) return false;
    return true;
} //}

int ClientConfig::loadFromFile(LoadCallback cb, void* data) //{
{
    uv_fs_t req;
    int fd = uv_fs_open(nullptr, &req, 
                      this->m_filename.c_str(), O_RDONLY,
                      0, nullptr);
    uv_fs_req_cleanup(&req);
    if(fd < 0) {
        this->m_error = "fail to open file";
        cb(errno, data);
        return -1;
    }

    int status = uv_fs_fstat(nullptr, &req, fd, nullptr);
    if(status < 0) {
        this->m_error = "fail to stat config file";
        uv_fs_close(nullptr, &req, fd, nullptr);
        uv_fs_req_cleanup(&req);
        cb(errno, data);
        return -1;
    }

    uv_buf_t* buf = new uv_buf_t();
    buf->base = (char*)malloc(uv_fs_get_statbuf(&req)->st_size + 1);
    buf->base[uv_fs_get_statbuf(&req)->st_size] = '\0';
    buf->len = uv_fs_get_statbuf(&req)->st_size;
    uv_fs_req_cleanup(&req);

    uv_fs_t* read_req = new uv_fs_t();
    uv_req_set_data((uv_req_t*)read_req, 
            new std::tuple<ClientConfig*, uv_file, uv_buf_t*, LoadCallback, void*>(this, fd, buf, cb, data));
    return uv_fs_read(this->mp_loop, read_req, fd, buf, 1, 0, ClientConfig::read_file_callback);

    /*
    uv_fs_req_cleanup(&req);
    if(nread != buf.len) {
        this->m_error = "fail to read config file";
        free(buf.base);
        uv_fs_close(nullptr, &req, fd, nullptr);
        uv_fs_req_cleanup(&req);
        cb(1, data);
        return -1;
    }

    json jsonx;
    try {
         jsonx = json::parse(std::string(buf.base)); // FIXME json error
    } catch (nlohmann::detail::parse_error err) {
        this->m_error = err.what();
        free(buf.base);
        uv_fs_close(nullptr, &req, fd, nullptr);
        uv_fs_req_cleanup(&req);
        cb(1, data);
        return -1;
    }

    free(buf.base);
    uv_fs_close(nullptr, &req, fd, nullptr);
    uv_fs_req_cleanup(&req);

    if(this->from_json(jsonx, cb, data) < 0) {
        cb(1, data);
        return -1;
    }
    cb(0, data);
    return 0;
    */
} //}

// static
void ClientConfig::read_file_callback(uv_fs_t* req) //{
{
    assert(uv_fs_get_type(req) == uv_fs_type::UV_FS_READ);
    std::tuple<ClientConfig*, uv_file, uv_buf_t*, LoadCallback, void*>* x = 
        (std::tuple<ClientConfig*, uv_file, uv_buf_t*, LoadCallback, void*>*)uv_req_get_data((uv_req_t*)req);
    ClientConfig* _this;
    uv_buf_t* uv_buf;
    uv_file file_fd;
    LoadCallback cb;
    void* data;
    std::tie(_this, file_fd, uv_buf, cb, data) = *x;
    delete x;

    uv_fs_req_cleanup(req);

    int open_status = uv_fs_get_system_error(req);
    if(open_status > 0) {
        _this->m_state = CONFIG_ERROR;
        _this->m_error = "fail to open file";
        Logger::logger->debug("%s", uv_buf->base); // TODO
        cb(open_status, data);

        free(uv_buf->base);
        delete uv_buf;

        uv_fs_close(_this->mp_loop, req, file_fd, ClientConfig::close_file_callback);

        return;
    }

    json jsonx;
    try {
         jsonx = json::parse(std::string(uv_buf->base)); // FIXME json error
    } catch (nlohmann::detail::parse_error err) {
        _this->m_error = err.what();
        free(uv_buf->base);
        cb(1, data);
        uv_fs_close(nullptr, req, file_fd, nullptr);
        uv_fs_req_cleanup(req);
        delete req;
        delete uv_buf;
        return;
    }

    free(uv_buf->base);
    uv_fs_close(nullptr, req, file_fd, nullptr);
    uv_fs_req_cleanup(req);
    delete req;
    delete uv_buf;

    if(_this->from_json(jsonx, cb, data) < 0) {
        cb(1, data);
        return;
    }
    cb(0, data);
    return;
} //}
void ClientConfig::close_file_callback(uv_fs_t* req) //{
{
    assert(uv_fs_get_type(req) == uv_fs_type::UV_FS_CLOSE);
    delete req;
} //}

int ClientConfig::from_json(const json& jsonx, LoadCallback cb, void* data) //{
{
    if(this->set_policy(jsonx) < 0) {
        this->m_state = CONFIG_ERROR;
        cb(95, data);
        return -1;
    }
    if(this->set_servers(jsonx) < 0) {
        this->m_state = CONFIG_ERROR;
        cb(95, data);
        return -1;
    }
    if(this->set_users(jsonx) < 0) {
        this->m_state = CONFIG_ERROR;
        cb(95, data);
        return -1;
    }
    this->m_state = CONFIG_SYNC;
    return 0;
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
int ClientConfig::set_policy(const json& jsonx) //{
{
    auto mode = jsonx["mode"];
    auto rule = jsonx["rule"];
    auto bind_address = jsonx["bind_address"];
    auto bind_port = jsonx["bind_port"];
    if(!mode.is_string()) {
        this->m_error = "invalid proxy mode";
        return -1;
    }
    if(!rule.is_string()) {
        this->m_error = "invalid proxy rule";
        return -1;
    }
    if(!bind_address.is_string()) return -1;
    if(!bind_port.is_string() && !bind_port.is_number()) return -1;

    if(mode.get<std::string>() == "global") {
        this->m_policy.m_mode = PROXY_MODE_GLOBAL;
    } else if(mode.get<std::string>() == "port") {
        this->m_policy.m_mode = PROXY_MODE_PORT;
    } else {
        return -1;
    }

    if(rule.get<std::string>() == "all") {
        this->m_policy.m_rule = PROXY_RULE_ALL;
    } else if(rule.get<std::string>() == "match") {
        this->m_policy.m_rule = PROXY_RULE_MATCH;
    } else if(rule.get<std::string>() == "nomatch") {
        this->m_policy.m_rule = PROXY_RULE_NOT_MATCH;
    } else {
        return -1;
    }

    uint32_t ipv4;
    if(str_to_ip4(bind_address.get<std::string>().c_str(), &ipv4) == false)
        return -1;
    this->m_policy.m_addr = ipv4;

    uint16_t port_x;
    if(!get_valid_port(bind_port, &port_x)) {
        return -1;
    }
    this->m_policy.m_port = port_x;

    return 0;
} //}
int ClientConfig::set_servers(const json& jsonx) //{
{
    this->m_servers.clear();
    if(jsonx.find("servers") == jsonx.end())
        return 0;

    if(!jsonx["servers"].is_array()) {
        this->m_error = "bad config format at 'servers'";
        return -1;
    }

    json m = jsonx["servers"];
    for(auto j = m.begin(); j != m.end(); j++) {
        if(!j->is_object()) {
            // TODO report bad format
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
            // TODO report bad format
            continue;
        }
        // TODO address check, cipher check, certificate check
        uint16_t port;
        if(!get_valid_port(j->at("port"), &port)) {
            // TODO report error
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
    return 0;
} //}
int ClientConfig::set_users(const json& jsonx) //{
{
    this->m_accounts.clear();
    if(jsonx.find("local_users") == jsonx.end())
        return 0;

    if(!jsonx["local_users"].is_array()) {
        this->m_error = "bad format in 'local_users'";
        return -1;
    }


    json m = jsonx["local_users"];
    for(auto j = m.begin(); j != m.end(); j++) {
        if(!j->is_object()) {
            // TODO report bad format
            continue;
        }
        if(!j->at("username").is_string() ||
           !j->at("password").is_string()
          ) {
            // TODO report bad format
            continue;
        }
        auto username    = j->at("username").get<std::string>();
        auto password    = j->at("password").get<std::string>();

        if(this->m_accounts.find(username) != this->m_accounts.end()) {
            // report duplicated username
            continue;
        }
        this->m_accounts[username] = password;
    }
    return 0;
} //}


int ClientConfig::writeToFile(WriteCallback cb, void* data) //{
{
    // TODO state ?
    auto json_data = this->to_json().dump(4);
    uv_fs_t req;
    int fd = uv_fs_open(nullptr, &req, 
                      this->m_filename.c_str(), O_WRONLY | O_TRUNC | O_CREAT,
                      S_IRWXU | S_IRWXG | S_IRWXO, nullptr);
    uv_fs_req_cleanup(&req);
    if(fd < 0) {
        this->m_error = "open file '" + this->m_filename + "' fail";
        cb(errno, data);
        return -1;
    }

    uv_buf_t* buf = new uv_buf_t();
    buf->base = (char*)malloc(json_data.size() + 1);
    memcpy(buf->base, json_data.c_str(), json_data.size() + 1);
    buf->len = json_data.size() + 1;

    uv_fs_t* write_req = new uv_fs_t();
    uv_req_set_data((uv_req_t*)write_req, 
            new std::tuple<ClientConfig*, uv_file, uv_buf_t*, WriteCallback, void*>(
                this, fd, buf, cb, data));

    uv_fs_write(this->mp_loop, write_req, fd, buf, 1, 0, ClientConfig::write_file_callback);
    return 0;
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
    result["bind_address"] = std::string(ip4_to_str(this->m_policy.m_addr));
    result["bind_port"]    = this->m_policy.m_port; // FIXME

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

// static
void ClientConfig::write_file_callback(uv_fs_t* req) //{
{
    assert(uv_fs_get_type(req) == uv_fs_type::UV_FS_WRITE);
    std::tuple<ClientConfig*, uv_file, uv_buf_t*, WriteCallback, void*>* x =
        (std::tuple<ClientConfig*, uv_file, uv_buf_t*, WriteCallback, void*>*) uv_req_get_data((uv_req_t*)req);
    ClientConfig* _this;
    uv_file file_fd;
    uv_buf_t* uv_buf;
    WriteCallback cb;
    void* data;
    std::tie(_this, file_fd, uv_buf, cb, data) = *x;

    int error_code = uv_fs_get_system_error(req);

    delete x;
    free(uv_buf->base);
    delete uv_buf;
    uv_fs_req_cleanup(req);

    if(error_code > 0) {
        _this->m_error = "write to file fail";
        cb(error_code, data);
    } else {
        cb(0, data);
    }

    uv_fs_close(_this->mp_loop, req, file_fd, ClientConfig::close_file_callback);
    return;
} //}

//}

