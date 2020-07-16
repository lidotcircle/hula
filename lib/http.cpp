#include "../include/http.hpp"

#include <sstream>
#include <cstring>

#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>


#define DEBUG(all...) __logger->debug(all)


//       << class Http >>      //{
Http::Http(const std::unordered_map<std::string, std::string>& default_response_header) //{
{
    this->m_default_response_header = default_response_header;
    this->m_state = HttpState::FINISH_PREV;
    this->m_current_request = nullptr;
    this->m_upgrade = false;
    this->m_chunk = false;
    http_parser_init(&this->m_parser, http_parser_type::HTTP_REQUEST);
    http_parser_settings_init(&this->m_parser_setting);
    this->m_parser_setting.on_message_begin    = http_on_message_begin;
    this->m_parser_setting.on_url              = http_on_url;
    this->m_parser_setting.on_status           = http_on_status;
    this->m_parser_setting.on_header_field     = http_on_field;
    this->m_parser_setting.on_header_value     = http_on_value;
    this->m_parser_setting.on_headers_complete = http_on_header_complete;
    this->m_parser_setting.on_body             = http_on_body;
    this->m_parser_setting.on_message_complete = http_on_message_complete;
    this->m_parser_setting.on_chunk_header     = http_on_chunk_header;
    this->m_parser_setting.on_chunk_complete   = http_on_chunk_complete;

    this->m_parser.data = this;
} //}

void Http::read_callback(ROBuf buf, int status) //{
{
    if(status < 0) return;
    ROBuf merge;
    if(this->m_remain.size() == 0) {
        merge = buf;
    } else {
        merge = this->m_remain + buf;
        merge = ROBuf();
    }
    http_parser_execute(&this->m_parser, &this->m_parser_setting, merge.base(), merge.size());
} //}

void Http::start_request() //{
{
    this->stop_read();
    assert(this->m_current_request == nullptr);
    assert(this->m_state == HttpState::MESSAGE_COMPLETE);
    assert(this->m_upgrade == false);
    if(this->m_parser.http_major != 1 || this->m_parser.http_minor != 1) {
        this->emit("error", new HttpArg::ErrorArgs("expect HTTP/1.1"));
        return;
    }
    this->m_current_request = new HttpRequest(this, this->m_default_response_header, 
            std::move(this->m_request_header),
            std::move(this->m_method),
            std::move(this->m_url),
            std::move(this->m_req_data));
    this->m_upgrade = (this->m_parser.upgrade == 1);
    if(this->m_upgrade) {
        this->emit("upgrade", new HttpArg::RequestArgs(this->m_current_request));
    } else {
        this->emit("request", new HttpArg::RequestArgs(this->m_current_request));
    }
} //}

void Http::response_write(ROBuf buf, WriteCallback cb, void* data) //{
{
    this->_write(buf, cb, data);
} //}

/** static */
int Http::http_on_message_begin(http_parser* parser) //{
{
    DEBUG("call %s", FUNCNAME);
    Http* _this = static_cast<decltype(_this)>(parser->data);
    assert(_this->m_state == HttpState::FINISH_PREV || _this->m_state == HttpState::MESSAGE_COMPLETE);
    _this->m_state = HttpState::MESSAGE_BEGIN;
    return 0;
} //}
int Http::http_on_url(http_parser* parser, const char* data, size_t len) //{
{
    DEBUG("call %s, url=%s", FUNCNAME, std::string(data, data + len).c_str());
    Http* _this = static_cast<decltype(_this)>(parser->data);
    if(_this->m_state == HttpState::URL) {
        _this->m_url += std::string(data, data + len);
        return 0;
    }
    assert(_this->m_state == HttpState::MESSAGE_BEGIN);
    _this->m_state = HttpState::URL;
    std::string str(data, data + len);
    _this->m_url = str;
    _this->m_method = http_method_str((enum http_method)parser->method);
    return 0;
} //}
int Http::http_on_status(http_parser* parser, const char* data, size_t len) //{
{
    DEBUG("call %s, status=%s", FUNCNAME, std::string(data, data + len).c_str());
    Http* _this = static_cast<decltype(_this)>(parser->data);
    _this->emit("error", new HttpArg::ErrorArgs("http request error"));
    __logger->warn("recieve a response ... OR FIXME");
    return 0;
} //}
int Http::http_on_field(http_parser* parser, const char* data, size_t len) //{
{
    DEBUG("call %s, field=%s", FUNCNAME, std::string(data, data + len).c_str());
    Http* _this = static_cast<decltype(_this)>(parser->data);
    if(_this->m_state == HttpState::FIELD) {
        _this->m_prev_field += std::string(data, data + len);
        return 0;
    }
    assert(_this->m_state == HttpState::URL || _this->m_state == HttpState::VALUE);
    _this->m_state = HttpState::FIELD;
    std::string field(data, data + len);
    _this->m_prev_field = field;
    return 0;
} //}
int Http::http_on_value(http_parser* parser, const char* data, size_t len) //{
{
    DEBUG("call %s, value=%s", FUNCNAME, std::string(data, data + len).c_str());
    Http* _this = static_cast<decltype(_this)>(parser->data);
    if(_this->m_state == HttpState::VALUE) {
        _this->m_request_header[_this->m_prev_field] += std::string(data, data + len);
        return 0;
    }
    assert(_this->m_state == HttpState::FIELD);
    _this->m_state = HttpState::VALUE;
    std::string value(data, data + len);
    _this->m_request_header[_this->m_prev_field] = value;
    return 0;
} //}
int Http::http_on_header_complete(http_parser* parser) //{
{
    DEBUG("call %s", FUNCNAME);
    Http* _this = static_cast<decltype(_this)>(parser->data);
    assert(_this->m_state == HttpState::VALUE);
    _this->m_state = HttpState::HEADER_COMPLETE;
    return 0;
} //}
int Http::http_on_body(http_parser* parser, const char* data, size_t len) //{
{ 
    DEBUG("call %s, body=%s", FUNCNAME, std::string(data, data + len).c_str());
    Http* _this = static_cast<decltype(_this)>(parser->data);
    if(_this->m_state == HttpState::BODY) {
        char* ddd = (char*)malloc(len);
        memcpy(ddd, data, len);
        _this->m_req_data = _this->m_req_data + ROBuf(ddd, len, 0, free);
        return 0;
    }
    assert(_this->m_state == HttpState::HEADER_COMPLETE);
    _this->m_state = HttpState::BODY;
    char* ddd = (char*)malloc(len);
    memcpy(ddd, data, len);
    _this->m_req_data = ROBuf(ddd, len, 0, free);
    return 0;
} //}
int Http::http_on_message_complete(http_parser* parser) //{
{
    DEBUG("call %s", FUNCNAME);
    Http* _this = static_cast<decltype(_this)>(parser->data);
    assert(_this->m_state == HttpState::BODY || 
            _this->m_state == HttpState::HEADER_COMPLETE);
    _this->m_state = HttpState::MESSAGE_COMPLETE;
    _this->start_request();
    return 0;
} //}
int Http::http_on_chunk_header(http_parser* parser) //{
{
    DEBUG("call %s", FUNCNAME);
    Http* _this = static_cast<decltype(_this)>(parser->data);
    _this->m_chunk = true;
    __logger->error("TODO"); // TODO
    return -1;
} //}
int Http::http_on_chunk_complete(http_parser* parser) //{
{
    DEBUG("call %s", FUNCNAME);
    Http* _this = static_cast<decltype(_this)>(parser->data);
    __logger->error("TODO"); // TODO
    return -1;
} //}

void Http::FinishRequest(HttpRequest* req) //{
{
    assert(this->m_current_request == req);
    assert(this->m_upgrade == false);
    this->m_current_request = nullptr;
    delete req;
    this->start_read();
    http_parser_init(&this->m_parser, http_parser_type::HTTP_REQUEST);
} //}
//}


//      << class HttpRequest >>            //{
HttpRequest::HttpRequest(Http* http, const std::unordered_map<std::string, std::string>& default_header,
        std::unordered_map<std::string, std::string>&& req_header,
        std::string&& method,
        std::string&& url,
        ROBuf&& request_data):
    m_header(), m_http(http), m_write_size(0), m_writeHeader(false),
    m_request_header(std::move(req_header)), m_method(std::move(method)),
    m_url(std::move(url)), m_request_data(std::move(request_data)), m_version("1.1") //{
{
    this->m_status = 0;
    this->m_chunk = false;
    this->m_end = false;
    for(auto& hh: default_header) this->setHeader(hh.first, hh.second);
} //}

void HttpRequest::setChunk() //{
{
    assert(this->m_chunk == false);
    this->m_chunk = true;
    this->setHeader("Transfer-Encoding", "chunked");
} //}

void HttpRequest::setStatus(uint16_t status, const char* statusText) //{
{
    this->m_status = status;
    if(statusText == nullptr)
        this->m_statusText = http_status_str((enum http_status)this->m_status);
    else
        this->m_statusText = statusText;
} //}
void HttpRequest::setHeader(const std::string& field, const std::string& value) //{
{
    assert(field.size() > 0);
    std::string res;
    bool upper = true;
    for(int i=0;i<field.size();i++) {
        if(upper) res.push_back(std::toupper(field[i]));
        else res.push_back(std::tolower(field[i]));

        if(field[i] == '-') upper = true;
        else upper = false;
    }
    this->m_header[res] = value;
} //}
void HttpRequest::writeHeader() //{
{
    assert(this->m_writeHeader == false);
    this->m_writeHeader = true;
    std::ostringstream str;
    if(this->m_status == 0) this->setStatus(200, nullptr);
    str << "HTTP/" << HTTP_VERSION << " " << this->m_status << " " << this->m_statusText << std::endl;
    for(auto& pair: this->m_header) 
        str << pair.first << ": " << pair.second << std::endl;
    str << std::endl;
    char* fff = (char*)malloc(str.str().size());
    std::memcpy(fff, str.str().c_str(), str.str().size());
    ROBuf buf(fff, str.str().size(), 0, free);
    auto chunk = this->m_chunk;
    this->m_chunk = false;
    this->write(buf, nullptr);
    this->m_chunk = chunk;
} //}
int  HttpRequest::write(ROBuf buf, WriteCallback cb) //{
{
    assert(this->m_end == false);
    assert(buf.size() > 0);
    if(!this->m_writeHeader)
        this->writeHeader();
    if(this->m_chunk) {
        char size_str[20];
        sprintf(size_str, "%lx\r\n", buf.size());
        buf = ROBuf(size_str, strlen(size_str)) + buf;
    }
    this->m_write_size += buf.size();
    int ret = 0;
    if(this->m_write_size > HTTP_MAX_WRITE_BUFFER_SIZE) {
        ret = this->m_write_size - HTTP_MAX_WRITE_BUFFER_SIZE;
    }
    auto ptr = new ResponseWriteData(cb, this);
    this->add_callback(ptr);
    this->m_http->response_write(buf, response_write_callback, ptr);
    return ret;
} //}
/** static */
void HttpRequest::response_write_callback(EventEmitter* obj, ROBuf buf, int status, void* data) //{
{ 
    ResponseWriteData* ddd = 
        dynamic_cast<decltype(ddd)>(static_cast<CallbackPointer*>(data));
    assert(ddd);
    WriteCallback cb = ddd->_cb;
    HttpRequest* req = ddd->_req;
    delete ddd;
    if(obj != nullptr) {
        req->remove_callback(ddd);
        req->m_write_size -= buf.size();
        if(status == 0 && req->m_write_size < HTTP_MAX_WRITE_BUFFER_SIZE && 
                (req->m_write_size + buf.size()) > HTTP_MAX_WRITE_BUFFER_SIZE) {
            req->emit("drain", nullptr);
        }
    } else {
        req = nullptr;
    }
    if(cb == nullptr)  return;

    if(obj == nullptr) return cb(nullptr, status);
    return cb(req, status);
} //}
void HttpRequest::end() //{
{
    assert(this->m_end == false);
    this->m_end = true;
    if(this->m_writeHeader == false)
        this->writeHeader();
    this->m_http->FinishRequest(this);
} //}
HttpRequest::~HttpRequest() {}
//}

__URL__ parse_url(const std::string& str) //{
{
    __URL__ ret;
    http_parser_url url;
    http_parser_url_init(&url);
    http_parser_parse_url(str.c_str(), str.size(), 0, &url);
    if(url.field_set & (1 << http_parser_url_fields::UF_USERINFO)) {
        const char* s = str.c_str() + url.field_data[http_parser_url_fields::UF_USERINFO].off;
        size_t len = url.field_data[http_parser_url_fields::UF_USERINFO].len;
        ret.m_userinfo = std::string(s, s + len);
    }
    if(url.field_set & (1 << http_parser_url_fields::UF_HOST)) {
        const char* s = str.c_str() + url.field_data[http_parser_url_fields::UF_HOST].off;
        size_t len = url.field_data[http_parser_url_fields::UF_HOST].len;
        ret.m_host = std::string(s, s + len);
    }
    if(url.field_set & (1 << http_parser_url_fields::UF_PORT)) {
        const char* s = str.c_str() + url.field_data[http_parser_url_fields::UF_PORT].off;
        size_t len = url.field_data[http_parser_url_fields::UF_PORT].len;
        ret.m_port = std::string(s, s + len);
    }
    if(url.field_set & (1 << http_parser_url_fields::UF_SCHEMA)) {
        const char* s = str.c_str() + url.field_data[http_parser_url_fields::UF_SCHEMA].off;
        size_t len = url.field_data[http_parser_url_fields::UF_SCHEMA].len;
        ret.m_schema = std::string(s, s + len);
    }
    if(url.field_set & (1 << http_parser_url_fields::UF_PATH)) {
        const char* s = str.c_str() + url.field_data[http_parser_url_fields::UF_PATH].off;
        size_t len = url.field_data[http_parser_url_fields::UF_PATH].len;
        ret.m_path = std::string(s, s + len);
    }
    if(url.field_set & (1 << http_parser_url_fields::UF_QUERY)) {
        const char* s = str.c_str() + url.field_data[http_parser_url_fields::UF_QUERY].off;
        size_t len = url.field_data[http_parser_url_fields::UF_QUERY].len;
        ret.m_query = std::string(s, s + len);
    }
    if(url.field_set & (1 << http_parser_url_fields::UF_FRAGMENT)) {
        const char* s = str.c_str() + url.field_data[http_parser_url_fields::UF_FRAGMENT].off;
        size_t len = url.field_data[http_parser_url_fields::UF_FRAGMENT].len;
        ret.m_fragment = std::string(s, s + len);
    }
    return ret;
} //}
std::string url_encode(const std::string& value) //{
{
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (std::string::const_iterator i = value.begin(), n = value.end(); i != n; ++i) {
        std::string::value_type c = (*i);

        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }

        // Any other characters are percent-encoded
        escaped << std::uppercase;
        escaped << '%' << std::setw(2) << int((unsigned char) c);
        escaped << std::nouppercase;
    }

    return escaped.str();
} //}
std::string url_decode(const std::string& value) //{
{
    std::ostringstream buf;
    bool percent = false;
    for(int i=0;i<value.size();i++) {
        if(value[i] == '%') {
            percent = true;
            continue;
        }
    }
    return buf.str();
} //}

