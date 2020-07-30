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

void writecb(HttpRequest* req) {
    if(req == nullptr) return;
    return;
}
void on_request(EventEmitter* target, const std::string& event, EventArgs::Base* argv) {
    Http* request = dynamic_cast<decltype(request)>(target);
    HttpArg::RequestArgs* reqarg = dynamic_cast<decltype(reqarg)>(argv);
    assert(request);
    assert(reqarg);
    auto req = reqarg->m_request;
    req->setChunk();
    req->write("hello\n\n", writecb);
    req->write("hello\n\n", writecb);
    req->end(nullptr);
}

void on_upgrade(EventEmitter* target, const std::string& event, EventArgs::Base* argv) {
    std::cout << "upgrade" << std::endl;
    Http* request = dynamic_cast<decltype(request)>(target);
    HttpArg::UpgradeArgs* reqarg = dynamic_cast<decltype(reqarg)>(argv);
    assert(request);
    assert(reqarg);
    auto req = reqarg->m_upgrade;
    req->write(ROBuf((char*)"hello\n\n", 7), writecb);
    req->write(ROBuf((char*)"hello\n\n", 7), writecb);
    req->RejectUpgrade("");
}

void on_error(EventEmitter* target, const std::string& event, EventArgs::Base* argv) {
    HttpArg::ErrorArgs* args = dynamic_cast<decltype(args)>(argv);
    assert(args);
    std::cout << "error raise with " << args->m_error << std::endl;
}

int main() {
    HttpMemory hhh;
    hhh.on("request", on_request);
    hhh.on("upgrade", on_upgrade);
    hhh.on("error", on_error);

    hhh << "GET" << " / HTTP/1.1\r\n" << 
        "H" << "ost:" <<  "www" << ".example1.com\r\n" <<
        "Connecti" << "on" << ": Kee" << "p-Alive\r\n" <<
        "Accept-Enco" << "ding" << ":" << " gzip\r\n" <<
        "Content-Length" << ": " << "12\r\n" <<
        "\r\n" <<
        "hello world!";

    hhh << "GET /index.html HTTP/1.1\r\n"
    "Host: www.example2.com\r\n"
    "Connection: upgrade\r\n"
    "Upgrade: example/1, foo/2f\r\n" << std::endl;

    hhh << 
        "GET / HTTP/1.1\r\n"
        "Host: www.example3.com\r\n"
        "Connection: Keep-Alive\r\n"
        "Accept-Encodeing: gzip\r\n"
        "Content-Length: 12\r\n\r\n"
        "Hello World!\r\n"

        "GET / HTTP/1.1\r\n"
        "Host: www.example4.com\r\n"
        "Connection: Keep-Alive\r\n"
        "Accept-Encodeing: gzip\r\n"
        "Content-Length: 12\r\n\r\n"
        "Hello World!\r\n";
    return 0;
}

