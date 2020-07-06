#pragma once

#include "proxyrule.h"
#include "config_file.h"
#include "file_libuv.h"


class ProxyConfig: public ConfigFile //{
{
    private:
        ProxyRuleMatcher m_matcher;

    protected:
        bool  fromROBuf(ROBuf buf) override;
        ROBuf toROBuf() override;

    public:
        ProxyConfig();
        void addRules(const std::vector<std::string>& rule);
        bool match(const std::string& addr, int port);
}; //}


class UVProxyConfig: public ProxyConfig, protected UVFile {
    public:
    inline UVProxyConfig(uv_loop_t* loop, const std::string& filename): ProxyConfig(), UVFile(loop, filename) {}
};

