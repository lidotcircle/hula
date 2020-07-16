#include "../include/proxyrule.h"
#include "../include/proxy_config.h"

#include <iostream>

#include <assert.h>


void test_matcher1() //{
{
    ProxyRuleMatcher matcher;
    matcher.add_proxy({"example", "com"}, 80);
    matcher.add_proxy({"google", "com"}, 80, true);
    matcher.add_proxy({"youtube", "com"}, 99, true);
    matcher.add_proxy({"youtube", "com"}, -1, true);
    matcher.add_proxy({"youtube", "com"}, 99, true);
    matcher.add_proxy({"mamamiya", "com"}, 99, true);
    matcher.add_exception({"xyz", "youtube", "com"}, -1, true);

    assert(!matcher.__match({""}, 80));
    assert(matcher.__match({"example", "com"}, 80));
    assert(matcher.__match({"example", "com", "cn"}, 80));
    assert(matcher.__match({"google", "com"}, 80));
    assert(matcher.__match({"www", "google", "com"}, 80));

    assert(matcher.match("www.google.com", 80));

    assert(matcher.__match({"www", "youtube", "com"}, 80));
    assert(matcher.__match({"www", "youtube", "com"}, 443));
    assert(!matcher.__match({"xyz", "youtube", "com"}, 443));
    assert(!matcher.__match({"www", "xyz", "youtube", "com"}, 443));

    for(auto& m: matcher.Export()) {
        std::cout << m << std::endl;
    }
} //}

void test_matcher2() //{
{
    ProxyRuleMatcher matcher;

    assert(matcher.add("www.google.com:443"));
    assert(matcher.add("www.google.com:22"));
    assert(matcher.add("|google"));

    assert(matcher.match("www.google.com", 443));
    assert(matcher.match("www.google.com", 22));
    assert(!matcher.match("www.google.com", 222));
    assert(matcher.match("google.cn", 221));

    for(auto& m: matcher.Export()) {
        std::cout << m << std::endl;
    }
} //}

void test_matcher3(uv_loop_t* loop) //{
{
    UVProxyConfig* config = new UVProxyConfig(loop, "../tests/gfwlist.txt");
    config->loadFromFile(nullptr, nullptr);

    config->setNewFile("./gfw");
    config->writeToFile(nullptr, nullptr);

    assert(config->match("google.com", 443));
    assert(config->match("google.com", 442));
    assert(!config->match("baidu.com", 442));
    assert(config->match("www.javlibrary.com", 80));
    assert(config->match("www.javlibrary.com", 443));
    assert(!config->match("www.javlibrary.com.cn", 443));

    delete config;
} //}

void test_matcher4(uv_loop_t* loop) //{
{
    UVProxyConfig* config = new UVProxyConfig(loop, "../tests/gfwlist.txt");
    config->loadFromFile(nullptr, nullptr);
} //}

int main() {
    uv_loop_t loop;
    uv_loop_init(&loop);

    test_matcher1();
    test_matcher2();
    test_matcher3(&loop);
//    test_matcher4(&loop);

    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
    return 0;
}
