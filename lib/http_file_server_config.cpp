#include "../include/http_file_server_config.h"
#include "../include/utils.h"


HttpFileServerConfig::HttpFileServerConfig() //{
{
    this->m_docroot = "/";
    this->m_bind_addr = 0;
    this->m_bind_port = 8877;
} //}

bool  HttpFileServerConfig::fromROBuf(ROBuf buf) //{
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
ROBuf HttpFileServerConfig::toROBuf() //{
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
bool HttpFileServerConfig::from_json(const json& data) //{
{
    if(!data.is_object()) {
        this->setError("bad format");
        return false;
    }

    if(data.find("document_root") == data.end() || 
       !data["document_root"].is_string()) {
        this->setError("document_root key required");
        return false;
    }
    this->m_docroot = data["document_root"].get<std::string>();

    if(data.find("bind_addr") == data.end()) {
        this->setError("bind_addr not found");
        return false;
    }
    if(!data["bind_addr"].is_string()) {
        this->setError("bind_addr: bad format");
        return false;
    }
    uint32_t addr;
    if(str_to_ip4(data["bind_addr"].get<std::string>().c_str(), &addr) == false) {
        this->setError("bind_addr: bad ipv4 address");
        return false;
    }
    this->m_bind_addr = k_ntohl(addr);
    

    if(data.find("bind_port") == data.end()) {
        this->setError("bind_port not found");
        return false;
    }
    if(!data["bind_port"].is_string() && !data["bind_port"].is_number()) {
        this->setError("bind_port: bad format");
        return false;
    }
    uint16_t port;
    if(get_valid_port(data["bind_port"], &port) == false) {
        logger->error("bad port");
        this->setError("bind_port: bad format");
        return false;
    }
    this->m_bind_port = port;

    return true;
} //}
json HttpFileServerConfig::to_json() //{
{
    json result = json::object();
    result["document_root"] = this->m_docroot;
    result["bind_addr"] = ip4_to_str(k_htonl(this->m_bind_addr));
    result["bind_port"] = this->m_bind_port;
    return result;
} //}

const std::string& HttpFileServerConfig::DocRoot() {return this->m_docroot;}
uint32_t HttpFileServerConfig::BindAddr() {return this->m_bind_addr;}
uint16_t HttpFileServerConfig::BindPort() {return this->m_bind_port;}

