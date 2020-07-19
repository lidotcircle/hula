#include "../include/http.h"
#include "../include/stream_memory.h"

class HttpMemory: public Http, public EBMemStream {
    public:
        HttpMemory(): Http(std::unordered_map<std::string, std::string>{{"Host", "www.baidu.com"}}), EBMemStream() {}
};

int http_on_field(http_parser* parser, const char* c, size_t len) {
    std::string s(c, c + len);
    std::cout << s << std::endl;
    return 0;
}


void test_http_parser() {
    const char* nnn = 
        "GET / HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "Connection: Keep-Alive\r\n"
        "Accept-Encoding: gzip\r\n"
        "\r\n";
    http_parser parser;
    http_parser_init(&parser, http_parser_type::HTTP_REQUEST);
    http_parser_settings setting;
    http_parser_settings_init(&setting);
    setting.on_header_field = http_on_field;
    setting.on_header_value = http_on_field;
    setting.on_url = http_on_field;
    int n = http_parser_execute(&parser, &setting, nnn, strlen(nnn));
}

void writecb(HttpRequest* req, int status) {
    if(req == nullptr) return;
    if(status != 0) {
        std::cout << "write fail" << std::endl;
        req->end();
        return;
    }
    return;
}
void on_request(EventEmitter* target, const std::string& event, EventArgs::Base* argv) {
    Http* request = dynamic_cast<decltype(request)>(target);
    HttpArg::RequestArgs* reqarg = dynamic_cast<decltype(reqarg)>(argv);
    assert(request);
    assert(reqarg);
    auto req = reqarg->m_request;
    req->setChunk();
    req->write(ROBuf((char*)"hello\n\n", 7), writecb);
    req->write(ROBuf((char*)"hello\n\n", 7), writecb);
    req->end();
}

void on_upgrade(EventEmitter* target, const std::string& event, EventArgs::Base* argv) {
    std::cout << "upgrade" << std::endl;
    Http* request = dynamic_cast<decltype(request)>(target);
    HttpArg::RequestArgs* reqarg = dynamic_cast<decltype(reqarg)>(argv);
    assert(request);
    assert(reqarg);
    auto req = reqarg->m_request;
    req->write(ROBuf((char*)"hello\n\n", 7), writecb);
    req->write(ROBuf((char*)"hello\n\n", 7), writecb);
}

int main() {
    HttpMemory hhh;
    hhh.on("request", on_request);
    hhh.on("upgrade", on_upgrade);

    hhh << "GET" << " / HTTP/1.1\r\n" << 
        "H" << "ost:" <<  "www" << ".example.com\r\n" <<
        "Connecti" << "on" << ": Kee" << "p-Alive\r\n" <<
        "Accept-Enco" << "ding" << ":" << " gzip\r\n" <<
        "Content-Length" << ": " << "12\r\n" <<
        "\r\n" <<
        "hello world!";

    hhh << "GET /index.html HTTP/1.1\r\n"
    "Host: www.example.com\r\n"
    "Connection: upgrade\r\n"
    "Upgrade: example/1, foo/2f\r\n" << std::endl;

    return 0;
}

