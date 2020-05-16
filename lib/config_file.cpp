#include "../include/config_file.h"
#include "../include/utils.h"

#include <assert.h>

#include <uv.h>


SingleServerInfo::SingleServerInfo(uint32_t addr,    uint16_t port, 
                                   const char* name, const char* pass,
                                   const char* cert, const char* cipher) //{
{
    this->m_addr = k_htons(addr);
    this->m_port = k_htons(port);

    this->m_user = std::string(name);
    this->m_pass = std::string(pass);
    this->m_cert = std::string(cert);
    this->m_cipher = std::string(cipher);
} //}

ClientConfig::ClientConfig(const char* filename) //{
{
    this->m_state = CONFIG_UNINIT;
    this->m_filename = std::string(filename);
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
    uv_fs_t* req = new uv_fs_t();
    uv_req_set_data((uv_req_t*)req, new std::tuple<ClientConfig*, void*>(this, data));
    return uv_fs_open(this->mp_loop, req, 
                      this->m_filename.c_str(), O_RDONLY, 
                      0, ClientConfig::open_file_callback);
} //}

// static
void ClientConfig::open_file_callback(uv_fs_t* req) //{
{
    std::tuple<ClientConfig*, void*>* x = (std::tuple<ClientConfig*, void*>*)uv_req_get_data((uv_req_t*)req);
    ClientConfig* _this;
    void* data;
    std::tie(_this, data) = *x;
    // TODO
} //}

