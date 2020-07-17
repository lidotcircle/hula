#pragma once

#include "events.h"
#include "config.h"
#include "object_manager.h"
#include "stream.hpp"

#include <http_parser.h>

#include <unordered_map>

#define HTTP_VERSION "1.1"

class Http;
/** << Event >>
 * @event drain 
 *     @param () */
namespace HttpRequestArg {
struct DrainArgs: public EventArgs::Base {};
}
class HttpRequest: virtual public CallbackManager, public EventEmitter //{
{
    public:
        /** if(req == nullptr) 
         *      write fail 
         *  else
         *      continue do something */
        using WriteCallback = void (*)(HttpRequest* req, int status);

    private:
        std::string m_method;
        std::string m_url;
        std::string m_version;
        ROBuf       m_request_data;
        std::unordered_map<std::string, std::string> m_request_header;

        std::unordered_map<std::string, std::string> m_header;

        Http* m_http;
        size_t m_write_size;

        uint16_t m_status;
        std::string m_statusText;

        bool m_chunk;
        bool m_end;

        bool m_writeHeader;

        static void response_write_callback(ROBuf buf, int status, void* data);

    public:
        HttpRequest(Http* http, const std::unordered_map<std::string, std::string>& default_header, 
                std::unordered_map<std::string, std::string>&& request_header,
                std::string&& method,
                std::string&& url,
                ROBuf&& req_data);

        inline std::string GetRequestHeader(const std::string& field) {
            if(this->m_request_header.find(field) != this->m_request_header.end())
                return this->m_request_header[field];
            else
                return "";
        }
        inline const std::unordered_map<std::string, std::string>& GetRequestHeaders() {return this->m_request_header;}
        void setChunk();
        void setStatus(uint16_t status, const char* statusText);
        void setHeader(const std::string& field, const std::string& value);
        void writeHeader();
        int  write(ROBuf buf, WriteCallback cb);
        void end();
        ~HttpRequest();
}; //}

enum HttpState {
    FINISH_PREV = 0,
    MESSAGE_BEGIN,
    METHOD,
    URL,
    FIELD,
    VALUE,
    HEADER_COMPLETE,
    BODY,
    MESSAGE_COMPLETE,
    CHUNK,
    CHUNK_COMPLETE
};
/** << Events >> //{
 * @event request 
 *     @param (HttpRequest* reqeust)
 * @event upgrade
 *     @param (HttpRequest* request)
 * @event error
 *     @param (std::string)
 *///}
namespace HttpArg {
struct RequestArgs: public EventArgs::Base {
    HttpRequest* m_request;
    inline RequestArgs(HttpRequest* request): m_request(request) {}
};
struct UpgradeArgs: public EventArgs::Base {
    HttpRequest* m_upgrade;
    inline UpgradeArgs(HttpRequest* upgrade): m_upgrade(upgrade) {}
};
struct ErrorArgs: public EventArgs::Base {
    std::string m_error;
    inline ErrorArgs(const std::string& error): m_error(error) {}
};
}
class Http: virtual public EBStreamAbstraction //{
{
    private:
        std::unordered_map<std::string, std::string> m_default_response_header;
        std::unordered_map<std::string, std::string> m_request_header;
        http_parser m_parser;
        http_parser_settings m_parser_setting;
        ROBuf m_remain;

        HttpRequest* m_current_request;

        HttpState m_state;
        std::string m_method;
        std::string m_url;
        std::string m_prev_field;
        ROBuf m_req_data;

        bool m_chunk;
        bool m_upgrade;

        void read_callback(ROBuf buf, int status) override;
        void end_signal() override;

        void should_start_write() override;
        void should_stop_write() override;

        static int http_on_message_begin(http_parser* parser);
        static int http_on_url(http_parser* parser, const char* data, size_t len);
        static int http_on_status(http_parser* parser, const char* data, size_t len);
        static int http_on_field(http_parser* parser, const char* data, size_t len);
        static int http_on_value(http_parser* parser, const char* data, size_t len);
        static int http_on_header_complete(http_parser* parser);
        static int http_on_body(http_parser* parser, const char* data, size_t len);
        static int http_on_message_complete(http_parser* parser);
        static int http_on_chunk_header(http_parser* parser);
        static int http_on_chunk_complete(http_parser* parser);

        void start_request();

        static void write_callback(EventEmitter*, ROBuf buf, int status, void* data);

    protected:
        void response_write(ROBuf buf, WriteCallback cb, void* data);
        void FinishRequest(HttpRequest*);
        friend class HttpRequest;

    public:
        Http(const std::unordered_map<std::string, std::string>& default_response_header);
}; //}

struct __URL__ {
    std::string m_schema;
    std::string m_userinfo;
    std::string m_host;
    std::string m_port;
    std::string m_path;
    std::string m_query;
    std::string m_fragment;
};
__URL__ parse_url(const std::string& str);

