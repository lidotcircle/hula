#include "../include/proxy_config.h"

#include <ctype.h>
#include <string.h>

#include <iostream>


ProxyConfig::ProxyConfig() {}
void ProxyConfig::addRules(const std::vector<std::string>& rules) //{
{
    for(auto& rule: rules) this->m_matcher.add(rule);
} //}
bool ProxyConfig::match(const std::string& addr, int port) {return this->m_matcher.match(addr, port);}

static void dummy_load_callback(int, void*) {}
void ProxyConfig::fileEventRaise(const std::string& filename, FileEventType event) //{
{
    std::cout << "file event raised" << std::endl;
    switch(event) {
        case RENAME:
            break;
        case CHANGE:
            this->loadFromFile(dummy_load_callback, nullptr);
            break;
    }
} //}

bool ProxyConfig::fromROBuf(ROBuf buf) //{
{
    int start = 0;
    int success = 0;
    const char* base = buf.base();

    ObjectChecker* checker = new ObjectChecker();
    this->SetChecker(checker);

    for(int i=0; i<buf.size(); i++) {
        if(base[i] == '\0') break;
        if(base[i] == '\r' || base[i] == '\n') {
            std::string line(base + start, base + i);
            start = i + 1;
            while(line.size() > 0) {
                if(isblank(line.front())) line.erase(0, 1);
                if(isblank(line.back()))  line.erase(line.size() - 1);
                if(!isblank(line.front()) && !isblank(line.back())) break;
            }
            if(line.size() == 0)    continue;
            if(line.front() == '!') continue;
            if(!checker->exist()) break;
            if(this->m_matcher.add(line)) success++;
        }
    }

    if(checker->exist()) this->cleanChecker(checker);
    delete checker;
    return true;
} //}
ROBuf ProxyConfig::toROBuf() //{
{
    auto all = this->m_matcher.Export();
    size_t total_size = 0;
    for(auto& x: all) total_size += (x.size() + 1);
    if(total_size == 0) return ROBuf((char*)"! Empty !", 9);

    char* buf = (char*)malloc(total_size);
    int s = 0;
    for(auto& x: all) {
        memcpy(buf + s, x.c_str(), x.size());
        s += x.size();
        buf[s] = '\n';
        s++;
    }
    return ROBuf(buf, total_size, 0, free);
} //}

