#include "../include/http.hpp"

int main() {
    auto url = parse_url("https://baby@google.com:443/?q=hello%20world#goodguy");
    assert(url.m_schema   == "https");
    assert(url.m_userinfo == "baby");
    assert(url.m_host     == "google.com");
    assert(url.m_port     == "443");
    assert(url.m_path     == "/");
    assert(url.m_query    == "q=hello%20world");
    assert(url.m_fragment == "goodguy");
    std::cout << "schema: "   << url.m_schema   << std::endl;
    std::cout << "userinfo: " << url.m_userinfo << std::endl;
    std::cout << "host: "     << url.m_host     << std::endl;
    std::cout << "port: "     << url.m_port     << std::endl;
    std::cout << "path: "     << url.m_path     << std::endl;
    std::cout << "query: "    << url.m_query    << std::endl;
    std::cout << "fragment: " << url.m_fragment << std::endl;
    std::string mm = "你好世界";
    std::cout << mm.size() << std::endl;
    return 0;
}

