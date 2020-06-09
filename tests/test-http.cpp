#include "../include/http.hpp"

class HttpMemory: virtual public Http, virtual public MemoryTCPAbstractConnection {
    public:
        HttpMemory(): Http(std::unordered_map<std::string, std::string>{{"Host", "www.baidu.com"}}), MemoryTCPAbstractConnection() {}
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

void on_request(EventEmitter* target, const std::string& event, EventArgs::Base* argv) {
    Http* request = dynamic_cast<decltype(request)>(target);
    HttpArg::RequestArgs* reqarg = dynamic_cast<decltype(reqarg)>(argv);
    assert(request);
    assert(reqarg);
    auto req = reqarg->m_request;
    req->write(ROBuf((char*)"hello", 5), nullptr);
    req->end();
}

int main() {
    Logger::logger_init_stdout();

//    test_http_parser();
//    return 0;
    HttpMemory hhh;
    hhh.on("request", on_request);
    hhh << "GE" << "T / HTTP/1.1\r\n" << 
        "H" << "ost:" <<  "www" << ".example.com\r\n" <<
        "Connecti" << "on" << ": Kee" << "p-Alive\r\n" <<
        "Accept-Enco" << "ding" << ":" << " gzip\r\n" <<
        "Content-Length" << ": " << "12\r\n" <<
        "\r\n" <<
        "hello world!";
    return 0;
}
