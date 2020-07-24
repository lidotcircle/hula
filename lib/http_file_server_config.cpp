#include "../include/http_file_server_config.h"


HttpFileServerConfig::HttpFileServerConfig() //{
{
    this->m_docroot = "/";
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

bool HttpFileServerConfig::from_json(const json& data) //{
{
    if(!data.is_object() || data.find("document_root") == data.end())
        return false;

    this->m_docroot = data["document_root"];
    return true;
} //}
json HttpFileServerConfig::to_json() //{
{
    json result = json::object();
    result["document_root"] = this->m_docroot;
    return result;
} //}

const std::string& HttpFileServerConfig::DocRoot() {return this->m_docroot;}

