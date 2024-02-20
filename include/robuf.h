#pragma once

#include <evtls/shared_memory.h>
#include <fstream>
#include <string.h>
using ROBuf = evtls::SharedMem;

inline ROBuf loadFile(const std::string& filename)
{
    std::ifstream f(filename, std::ios::in);
    if (f.bad()) {
        return ROBuf();
    }
    std::string conf;
    while (true) {
        char buf[4096];
        const auto n = f.readsome(buf, sizeof(buf));
        if (n == 0) break;
        conf += std::string(buf, n);
    }
    ROBuf buf(conf.size());
    memcpy(buf.__base(), conf.c_str(), conf.size());
    return buf;
}
