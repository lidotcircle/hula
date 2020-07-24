#pragma once

#include "events.h"
#include "config.h"
#include "object_manager.h"
#include "stream.h"
#include "robuf.h"

#include <http_parser.h>

#include <evtls/help_class.h>
using namespace evtls;

#include <unordered_map>

#define HTTP_VERSION "1.1"


#define XXX(a, b, c) b = a, 
enum HttpStatus {
    HTTP_STATUS_MAP(XXX)
};
#undef  XXX


class Http;
/** << Event >> //{
 * @event drain 
 *     @param () */
namespace HttpRequestArg {
struct DrainArgs: public EventArgs::Base {};
} //}
class HttpRequest: virtual public CallbackManager, public EventEmitter //{
{
    public:
        using WriteCallback = void (*)(HttpRequest* req);
        struct Info {
            inline virtual ~Info() {}
        };


    private:
        std::string m_method;
        std::string m_url;
        std::string m_version;
        ROBuf       m_request_data;
        std::unordered_map<std::string, std::string> m_request_header;

        std::unordered_map<std::string, std::string> m_header;

        Http* m_http;
        Info* m_info;

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
        inline const std::string& GetURL() {return this->m_url;}
        inline const std::string& GetMethod() {return this->m_method;}
        inline const ROBuf        GetData() {return this->m_request_data;}
        void setChunk();
        void setStatus(HttpStatus status, const char* statusText = nullptr);
        void setHeader(const std::string& field, const std::string& value);
        void writeHeader();
        int  write(ROBuf buf,       WriteCallback cb = nullptr);
        int  write(const char* buf, WriteCallback cb = nullptr);
        void end(ROBuf buf);
        void end(const char* buf);

        EBStreamAbstraction::UNST AcceptUpgrade(ROBuf buf);
        EBStreamAbstraction::UNST AcceptUpgrade(const char* buf);
        void                      RejectUpgrade(ROBuf buf);
        void                      RejectUpgrade(const char* buf);

        Info* GetInfo();
        void  SetInfo(Info*);
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
 * @event upgraded
 *     @param ()
 */
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
struct UpgradedArgs: public EventArgs::Base {};
} //}
class Http: virtual public EBStreamAbstraction, virtual public StoreFetchPointer //{
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

        size_t m_writed_buffer_size;

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

        static void response_write_callback(ROBuf buf, int status, void* data);

    protected:
        int  response_write(ROBuf buf, WriteCallback cb, void* data);
        void FinishRequest(HttpRequest*);
        UNST FinishUpgradeAccept(HttpRequest*);
        void FinishUpgradeReject(HttpRequest*);
        friend class HttpRequest;

    public:
        Http(const std::unordered_map<std::string, std::string>& default_response_header);

        void PushFirst(ROBuf buf);
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


#include "stream_libuv.h"
class UVHttp: public Http, public EBStreamUV {
    public:
       inline UVHttp(const std::unordered_map<std::string, std::string>& dh, uv_tcp_t* tcp):
           Http(dh), EBStreamUV(tcp) {this->start_read();}
};

