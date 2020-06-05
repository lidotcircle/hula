#pragma once

#include "tcpabstraction.h"
#include "events.h"

#include <unordered_map>

class HttpRequest: public TCPAbstractConnection<HttpRequest> {
    private:
        std::string m_method;
        std::string m_url;
        std::string m_version;

        std::unordered_map<std::string, std::string> m_header;

    public:
        HttpRequest(const std::unordered_map<std::string, std::string>& default_header);
        void setHeader(const std::string& field, const std::string& value);
        void writeHeader();
        void write(ROBuf buf);
        void end();
};

/** << Events >> //{
 * @event request 
 *     @param (HttpRequest* reqeust)
 * @event upgrade
 *     @param (HttpRequest* request)
 * @event error
 *     @param (std::exception)
 *///}
class Http: public EventEmitter, public TCPAbstractConnection<Http> {
    public:
};

