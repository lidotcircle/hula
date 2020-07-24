#include "../include/http_file_server.h"
#include "../include/utils.h"
#include "../include/base64.h"
#include "../include/config.h"

#include <chrono>
#include <time.h>
#include <filesystem>
#include <map>

#define DEBUG(all...) __logger->debug(all)

#define FILE_MAX_READ_SIZE (1024 * 512)
#define COM__MIN(a, b) (a < b ? a : b)

static std::string tolower_(std::string str) //{
{
    for(size_t i=0;i<str.size();i++)
        str[i] = std::tolower(str[i]);
    return str;
} //}
static std::string toupper_(std::string str) //{
{
    for(size_t i=0;i<str.size();i++)
        str[i] = std::toupper(str[i]);
    return str;
} //}

static const std::map<std::string, std::string> content_type_map = //{
{
    {".aac",    "audio/aac"},
    {".abw",    "application/x-abiword"},
    {".arc",    "application/x-freearc"},
    {".avi",    "video/x-msvideo"},
    {".azw",    "application/vnd.amazon.ebook"},
    {".bin",    "application/octet-stream"},
    {".bmp",    "image/bmp"},
    {".bz",     "application/x-bzip"},
    {".bz2",    "application/x-bzip2"},
    {".csh",    "application/x-csh"},
    {".css",    "text/css"},
    {".csv",    "text/csv"},
    {".doc",    "application/msword"},
    {".docx",   "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {".eot",    "application/vnd.ms-fontobject"},
    {".epub",   "application/epub+zip"},
    {".gz",     "application/gzip"},
    {".gif",    "image/gif"},
    {".htm",    "text/html"},
    {".html",   "text/html"},
    {".ico",    "image/vnd.microsoft.icon"},
    {".ics",    "text/calendar"},
    {".jar",    "application/java-archive"},
    {".jpg",    "image/jpeg"},
    {".jpeg",   "image/jpeg"},
    {".js",     "text/javascript"},
    {".json",   "application/json"},
    {".jsonld", "application/ld+json"},
    {".mid",    "audio/x-midi"},
    {".midi",   "audio/x-midi"},
    {".mjs",    "text/javascript"},
    {".mp3",    "audio/mpeg"},
    {".mpeg",   "video/mpeg"},
    {".mpkg",   "application/vnd.apple.installer+xml"},
    {".odp",    "application/vnd.oasis.opendocument.presentation"},
    {".ods",    "application/vnd.oasis.opendocument.spreadsheet"},
    {".odt",    "application/vnd.oasis.opendocument.text"},
    {".oga",    "audio/ogg"},
    {".ogv",    "video/ogg"},
    {".ogx",    "application/ogg"},
    {".opus",   "audio/opus"},
    {".otf",    "font/otf"},
    {".png",    "image/png"},
    {".pdf",    "application/pdf"},
    {".php",    "application/php"},
    {".ppt",    "application/vnd.ms-powerpoint"},
    {".pptx",   "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {".rar",    "application/vnd.rar"},
    {".rtf",    "application/rtf"},
    {".sh",     "application/x-sh"},
    {".svg",    "image/svg+xml"},
    {".swf",    "application/x-shockwave-flash"},
    {".tar",    "application/x-tar"},
    {".tif",    "image/tiff"},
    {".tiff",   "image/tiff"},
    {".ts",     "video/mp2t"},
    {".ttf",    "font/ttf"},
    {".txt",    "text/plain"},
    {".vsd",    "application/vnd.visio"},
    {".wav",    "audio/wav"},
    {".weba",   "audio/webm"},
    {".webm",   "video/webm"},
    {".webp",   "image/webp"},
    {".woff",   "font/woff"},
    {".woff2",  "font/woff2"},
    {".xhtml",  "application/xhtml+xml"},
    {".xls",    "application/vnd.ms-excel"},
    {".xlsx",   "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {".xml",    "application/xml"},
    {".xul",    "application/.vndmozilla.xul+xml"},
    {".zip",    "application/zip"},
    {".3gp",    "video/3gpp"},
    {".3g2",    "video/3gpp2"},
    {".7z",     "application/x-7z-compressed"},
    {"unknown", "application/octet-stream"}
}; //}

HttpFileServer::HttpFileServer(std::shared_ptr<HttpFileServerConfig> config): m_config(config) //{
{
    DEBUG("call %s", FUNCNAME);
    this->m_upgrade_handler = nullptr;
    this->m_ws_handler = nullptr;
    this->m_upgrade_data = nullptr;
} //}

/** implement virtual methods */
void HttpFileServer::on_connection(UNST con) //{
{
    DEBUG("call %s", FUNCNAME);
    this->EmitAnConnection(con, ROBuf());
} //}

void HttpFileServer::register_listeners(Http* session) //{
{
    DEBUG("call %s", FUNCNAME);
    session->on("upgrade", upgrade_listener);
    session->on("upgraded", upgraded_listener);
    session->on("request", request_listener);
    session->on("error", error_listener);
} //}

struct __request_keep_state: public CallbackPointer {
    HttpFileServer::FileServerRequestInfo* _info;
    inline __request_keep_state(decltype(_info) info): _info(info) {}
};

static std::pair<int, int> parse_range_pair(std::string range) //{
{
    DEBUG("call %s", FUNCNAME);
    int r1 = -1, r2 = -1;
    if(range.size() < 8 || range.substr(0, 6) != "bytes=")
        return std::make_pair(r1, r2);

    auto pos = range.find('-');
    if(pos == std::string::npos || (pos + 1) >= range.size())
        return std::make_pair(r1, r2);

    std::string r1s = range.substr(6, pos);
    std::string r2s = range.substr(pos + 1);

    r1 = atoi(r1s.c_str());
    r2 = atoi(r2s.c_str());
    if(r1 == 0) {
        if(r1s.size() != 1 || r1s[0] != '0')
            r1 = -1;
    }
    if(r2 == 0) {
        if(r2s.size() != 1 || r2s[0] != '0') {
            r1 = -1;
            r2 = -1;
        }
    }

    return std::make_pair(r1, r2);
} //}
static void close_request_with_bad_status(HttpRequest* req, HttpStatus status, const char* msg) //{
{
    DEBUG("call %s", FUNCNAME);
    req->setStatus(status);
    req->setHeader("Connection", "Close");
    req->end(msg);
} //}
#define GET_REQ_STATE() \
    __request_keep_state* msg =  \
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data)); \
    assert(msg); \
    auto _this = msg->_info->_this; \
    auto info = msg->_info; \
    auto request = msg->_info->request; \
    auto http = msg->_info->http; \
    auto file = msg->_info->file; \
    auto run = msg->CanRun(); \
    delete msg; \
    if(!run) return; \
    info->remove_callback(msg)

static void file_read_callback(ROBuf buf, int status, void* data);
static void read_file_to_stream(HttpRequest* request) //{
{
    DEBUG("call %s", FUNCNAME);
    auto __info = request->GetInfo();
    HttpFileServer::FileServerRequestInfo* info = dynamic_cast<decltype(info)>(__info); assert(info);

    if(info->end_pos == info->cur_pos) {
        request->end(nullptr);
        return;
    }

    auto read_size = COM__MIN(FILE_MAX_READ_SIZE, info->end_pos - info->cur_pos);

    auto ptr = new __request_keep_state(info);
    info->add_callback(ptr);
    info->file->read(info->cur_pos + 1, read_size, file_read_callback, ptr);
} //}
static void file_read_callback(ROBuf buf, int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    GET_REQ_STATE();

    if(status < 0) {
        http->emit("error", new HttpArg::ErrorArgs("fail to read file"));
        return;
    }

    assert(buf.size() > 0);
    info->cur_pos += buf.size();
    request->write(buf);
    read_file_to_stream(request);
} //}
static void file_stat_callback(std::shared_ptr<Stat> stat, int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    GET_REQ_STATE();

    if(status < 0) {
        close_request_with_bad_status(request, HttpStatus::INTERNAL_SERVER_ERROR, "<h1>INTERNAL SERVER ERROR</h1>");
        return;
    }

    auto range = request->GetRequestHeader("Range");
    auto range_pair = parse_range_pair(range);

    request->setHeader("Accept-Ranges", "bytes");
    request->setHeader("Content-Length", std::to_string(stat->st_size));
    request->setHeader("Last-Modified", time_t_to_UTCString(stat->st_mtim));

    if(range_pair.first != -1) {
        request->setHeader("Content-Range", "bytes " + 
                std::to_string(range_pair.first) + "-" + std::to_string(range_pair.second) 
                + "/" + std::to_string(stat->st_size));
        if(range_pair.first >= stat->st_size ||
           range_pair.second >= stat->st_size ||
           range_pair.first > range_pair.second) {
            close_request_with_bad_status(request, HttpStatus::BAD_REQUEST, "<h1>bad Range</h1>");
            return;
        } else {
            info->start_pos = range_pair.first;
            info->end_pos   = range_pair.second;
            info->cur_pos   = range_pair.first - 1;
        }
    } else {
        info->start_pos = 0;
        info->end_pos   = stat->st_size - 1;
        info->cur_pos   = -1;
    }

    if(range_pair.first != -1)
        request->setStatus(HttpStatus::PARTIAL_CONTENT);
    else
        request->setStatus(HttpStatus::OK);

    if(request->GetMethod() == "HEAD" || stat->st_size == 0) {
        request->writeHeader();
        return;
    }

    read_file_to_stream(request);
} //}
static void file_open_callback(int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    GET_REQ_STATE();

    if(status < 0) {
        close_request_with_bad_status(request, HttpStatus::NOT_FOUND, "<h1>Not Found</h1>");
        return;
    }

    auto ptr = new __request_keep_state(info);
    info->add_callback(ptr);
    file->stat(file_stat_callback, ptr);
} //}


#define GETTHIS(argt, en) \
    Http* http = dynamic_cast<decltype(http)>(obj); assert(http); \
    HttpFileServer* _this = static_cast<decltype(_this)>(http->FetchPtr()); \
    HttpArg::argt* args = dynamic_cast<decltype(args)>(aaa); assert(args); \
    assert(eventname == en);
void HttpFileServer::upgrade_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    DEBUG("call %s", FUNCNAME);
    GETTHIS(UpgradeArgs, "upgrade");

    auto upgrade = args->m_upgrade;

    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    upgrade->setHeader("Date", time_t_to_UTCString(now));
    upgrade->setHeader("Server", "Unknown");

    if(upgrade->GetRequestHeader("Connection").size() == 0 ||
       tolower_(upgrade->GetRequestHeader("Connection")) != "upgrade") {
        upgrade->setStatus(HttpStatus::BAD_REQUEST);
        upgrade->RejectUpgrade("<h1>bad ws request</h1>");
        return;
    }

    UpgradeRequestIMPL* rr = new UpgradeRequestIMPL(upgrade);
    if(_this->m_upgrade_handler != nullptr) {
        _this->m_upgrade_handler(rr, _this->m_upgrade_data);
    } else if (_this->m_ws_handler != nullptr) {
        _this->ws_upgrade_preprocess(upgrade, rr);
    } else {
        upgrade->setStatus(HttpStatus::BAD_REQUEST);
        upgrade->RejectUpgrade("<h1>bad ws request</h1>");
        return;
    }
    delete rr;
} //}
void HttpFileServer::upgraded_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    DEBUG("call %s", FUNCNAME);
    GETTHIS(UpgradedArgs, "upgraded");
    delete obj;
} //}
void HttpFileServer::request_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    DEBUG("call %s", FUNCNAME);
    GETTHIS(RequestArgs, "request");

    auto request = args->m_request;
    auto method  = request->GetMethod();
    auto data    = request->GetData();
    auto __url   = parse_url(request->GetURL());

    if(__url.m_path.size() > 0 && __url.m_path.back() == '/')
        __url.m_path += "index.html";

    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    request->setHeader("Date", time_t_to_UTCString(now));
    request->setHeader("Server", "Unknown");
    std::string location = "http://" + request->GetRequestHeader("Host") + __url.m_path;
    request->setHeader("Location", location);

    if(__url.m_path.size() == 0 ||
       __url.m_path.front() != '/') {
        close_request_with_bad_status(request, HttpStatus::BAD_REQUEST, "<h1>bad request</h1>");
        return;
    }

    if(method != "GET" && method != "HEAD") {
        close_request_with_bad_status(request, HttpStatus::METHOD_NOT_ALLOWED, "<h1>Bad Method</h1>");
        return;
    }

    std::filesystem::path filepath = std::filesystem::absolute(_this->m_config->DocRoot()).lexically_normal();
    filepath.append(__url.m_path.substr(1));
    if(!filepath.has_extension()) {
        auto unknown = content_type_map.find("unknown");
        assert(unknown != content_type_map.end());
        request->setHeader("Content-Type", unknown->second);
    } else {
        std::string extension = filepath.extension();
        if(content_type_map.find(extension) == content_type_map.end()) {
            auto unknown = content_type_map.find("unknown");
            assert(unknown != content_type_map.end());
            request->setHeader("Content-Type", unknown->second);
        } else {
            auto type = content_type_map.find(extension);
            request->setHeader("Content-Type", type->second);
        }
    }

    FileServerRequestInfo* info = new FileServerRequestInfo();
    request->SetInfo(info);
    info->file    = _this->createFile(filepath);
    info->http    = http;
    info->_this   = _this;
    info->request = request;

    if(info->file == nullptr) {
        close_request_with_bad_status(request, HttpStatus::INTERNAL_SERVER_ERROR, "<h1>Internal Server Error</h1>");
        return;
    }

    auto ptr = new __request_keep_state(info);
    info->add_callback(ptr);
    info->file->open(O_RDONLY, 0666, file_open_callback, ptr);
} //}
void HttpFileServer::error_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    DEBUG("call %s", FUNCNAME);
    GETTHIS(ErrorArgs, "error");
    _this->FinishSession(http);
} //}
#undef GETTHIS


void HttpFileServer::ws_upgrade_preprocess(HttpRequest* request, UpgradeRequest* rr) //{
{
    if(request->GetRequestHeader("Upgrade").size() == 0 ||
       tolower_(request->GetRequestHeader("Upgrade")) != "websocket") {
        request->setStatus(HttpStatus::BAD_REQUEST);
        request->RejectUpgrade("<h1>bad request</h1>");
        return;
    }

    auto version = request->GetRequestHeader("Sec-WebSocket-Version");
    if(version.size() == 0 || atoi(version.c_str()) < 13) {
        request->setStatus(HttpStatus::BAD_REQUEST);
        request->RejectUpgrade("<h1>bad ws version</h1>");
        return;
    }

    auto key = request->GetRequestHeader("Sec-WebSocket-Key");
    if(key.size() == 0) {
        request->setStatus(HttpStatus::BAD_REQUEST);
        request->RejectUpgrade("<h1>ws \"Sec-WebSocket-Key\" field is empty</h1>");
        return;
    }

    key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    auto sha1 = Sha1Bin(key.c_str(), key.size());
    std::string keysha1(28, '=');
    auto n    = Base64Encode(sha1, 20, (char*)keysha1.c_str(), 28);
    assert(n == 28);
    request->setHeader("Sec-WebSocket-Accept", keysha1);
    request->setHeader("Sec-WebSocket-Version", "13");

    if(this->m_ws_handler == nullptr) {
        request->setStatus(HttpStatus::BAD_REQUEST);
        request->RejectUpgrade(nullptr);
        return;
    }

    this->m_ws_handler(rr, this->m_upgrade_data);
} //}

void HttpFileServer::EmitAnConnection(UNST con, ROBuf firstPacket) //{
{
    DEBUG("call %s", FUNCNAME);
    auto http = this->createHttpSession(con);
    http->StorePtr(this);
    this->register_listeners(http);
    this->m_sessions.insert(http);
    if(firstPacket.size() > 0)
        http->PushFirst(firstPacket);
} //}
void HttpFileServer::FinishSession(Http* http) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_sessions.find(http) != this->m_sessions.end());
    this->m_sessions.erase(this->m_sessions.find(http));
    http->StorePtr(nullptr);
    delete http;
} //}

void HttpFileServer::drain_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* aaa) //{
{
    DEBUG("call %s", FUNCNAME);
} //}

void HttpFileServer::SetUpgradeHandler(UpgradeHandler h) //{
{
    this->m_upgrade_handler = h;
} //}
void HttpFileServer::SetWSHandler(UpgradeHandler h) //{
{
    this->m_ws_handler = h;
} //}
void HttpFileServer::SetUpgradeData(UpgradeExtraData* data) //{
{
    this->m_upgrade_data = data;
} //}

void HttpFileServer::close() {this->emit("dead", new EventArgs::Base());}

HttpFileServer::~HttpFileServer() //{
{
    for(auto& session: this->m_sessions)
        delete session;
    if(this->m_upgrade_data) {
        delete this->m_upgrade_data;
        this->m_upgrade_data = nullptr;
    }
} //}



HttpFileServer::UpgradeRequestIMPL::UpgradeRequestIMPL(HttpRequest* request) //{
{
    this->m_request = request;
} //}
void HttpFileServer::UpgradeRequestIMPL::reject() //{
{
    this->m_request->setStatus(HttpStatus::BAD_REQUEST);
    this->m_request->RejectUpgrade(nullptr);
} //}
EBStreamAbstraction::UNST HttpFileServer::UpgradeRequestIMPL::accept() //{
{
    this->m_request->setStatus(HttpStatus::SWITCHING_PROTOCOLS);
    return this->m_request->AcceptUpgrade(nullptr);
} //}

std::string HttpFileServer::UpgradeRequestIMPL::value(const std::string& field) //{
{
    return this->m_request->GetRequestHeader(field);
} //}
std::string HttpFileServer::UpgradeRequestIMPL::url() //{
{
    return this->m_request->GetURL();
} //}
ROBuf       HttpFileServer::UpgradeRequestIMPL::data() //{
{
    return this->m_request->GetData();
} //}

void HttpFileServer::UpgradeRequestIMPL::setHeader(const std::string& field, const std::string& value) //{
{
    this->m_request->setHeader(field, value);
} //}
