#include "../include/proxyrule.h"
#include "../include/http.hpp"

#include <assert.h>

std::map<std::string, int> schema_port = {{"http", 80}, {"https", 443}, {"ssh", 22}, {"ftp", 21}};
std::map<int, std::string> port_schema = {{80, "http"}, {443, "https"}, {22, "ssh"}, {21, "ftp"}};


DomainMatcher::DomainMatcher(): m_children(), m_ports(), m_matcher_here(false) {}

void DomainMatcher::add(const std::vector<std::string>& domain, int port) //{
{
    if(domain.size() == 0) return;
    this->__add(domain, port, 0);
} //}
void DomainMatcher::__add(const std::vector<std::string>& domain, int port, int n) //{
{
    if(domain.size() == n) {
        this->m_matcher_here = true;
        if(port > 0) {
            if(this->m_ports.find(-1) == this->m_ports.end())
                this->m_ports.insert(port);
        } else {
            this->m_ports.clear();
            this->m_ports.insert(-1);
        }
        return;
    } else {
        if(this->m_children.find(domain[n]) == this->m_children.end()) {
            auto new_child = new DomainMatcher();
            this->m_children[domain[n]] = new_child;
        }
        this->m_children[domain[n]]->__add(domain, port, n + 1);
    }
} //}

bool DomainMatcher::match(const std::vector<std::string>& domain, int port) //{
{
    if(domain.size() == 0) return false;
    return this->__match(domain, port, 0);
} //}
bool DomainMatcher::__match(const std::vector<std::string>& domain, int port, int n) //{
{
    if(this->m_matcher_here) {
        if(this->m_ports.find(-1)   != this->m_ports.end()) return true;
        if(this->m_ports.find(port) != this->m_ports.end()) return true;
    }
    if(domain.size() == n) return false;
    if(this->m_children.find(domain[n]) == this->m_children.end()) return false;
    return this->m_children[domain[n]]->__match(domain, port, n + 1);
} //}

std::vector<std::string> DomainMatcher::Export(const std::string& prefix, bool reversal) //{
{
    std::vector<std::string> ret;
    std::vector<std::string> history;
    this->__export(prefix, reversal, history, ret);
    return ret;
} //}
void DomainMatcher::__export(const std::string& prefix, bool reversal, 
                             std::vector<std::string>& _history, std::vector<std::string>& _exports) //{
{
    if(this->m_matcher_here) {
        for(auto port: this->m_ports) {
            std::string schema;
            if(port_schema.find(port) != port_schema.end()) schema = port_schema[port] + "://";
            std::string result = prefix + schema;
            if(port == -1) result = prefix;
            if(reversal) {
                for(auto x=_history.rbegin(); x!=_history.rend(); x++)
                    result = result + *x + ".";
            } else {
                for(auto x=_history.begin();  x!=_history.end(); x++)
                    result = result + *x + ".";
            }
            if(result.size() > 0)
                result.erase(result.size() - 1);

            if(port_schema.find(port) == port_schema.end() && port > 0)
                result = result + ":" + std::to_string(port);
            if(result.size() > 0)
                _exports.push_back(result);
        }
    }
    for(auto& next: this->m_children) {
        _history.push_back(next.first);
        next.second->__export(prefix, reversal, _history, _exports);
        _history.pop_back();
    }
} //}

DomainMatcher::~DomainMatcher() //{
{
    for(auto& child: this->m_children)
        delete child.second;
} //}


__ProxyRuleMatcher::__ProxyRuleMatcher(): m_forward(), m_reversal() {}

void __ProxyRuleMatcher::add(const std::vector<std::string>& domain, int port, bool reversal) //{
{
    if(reversal) {
        std::vector<std::string> rdomain;
        for(auto m=domain.rbegin(); m!=domain.rend(); m++)
            rdomain.push_back(*m);
        this->m_reversal.add(rdomain, port);
    } else {
        this->m_forward.add(domain, port);
    }
} //}
bool __ProxyRuleMatcher::match(const std::vector<std::string>& domain, int port) //{
{
    auto f = this->m_forward.match(domain, port);
    std::vector<std::string> reverse;
    for(auto m = domain.rbegin(); m!=domain.rend(); m++)
        reverse.push_back(*m);
    auto r = this->m_reversal.match(reverse, port);
    return (f || r);
} //}

std::vector<std::string> __ProxyRuleMatcher::Export(const std::string& prefix) //{
{
    auto a = this->m_forward. Export(prefix + "|", false);
    auto b = this->m_reversal.Export(prefix + "||", true);
    for(auto& x: b)
        a.push_back(std::move(x));
    return a;
} //}


ProxyRuleMatcher::ProxyRuleMatcher(): m_proxy(), m_exception() {}

static std::vector<std::string> break_string_by_dot(const std::string& address) //{
{
    std::vector<std::string> search;
    int start = 0;
    for(int i=0; i<address.size(); i++) {
        if(address[i] == '.') {
            search.push_back(std::string(address.c_str() + start, address.c_str() + i));
            start = i + 1;
        }
    }
    search.push_back(std::string(address.c_str() + start, address.c_str() + address.size()));
    return search;
} //}
bool ProxyRuleMatcher::match(const std::string& address, int port) //{
{
    return this->__match(break_string_by_dot(address), port);
} //}
bool ProxyRuleMatcher::__match(const std::vector<std::string>& domain, int port) //{
{
    auto a = this->m_proxy.match(domain, port);
    auto b = this->m_exception.match(domain, port);
    return (a && !b);
} //}
enum __RuleState {BEGIN, F_AT, FS_AT, F_S, FS_S, FS_AT_T_S, FS_AT_TF_S};
bool ProxyRuleMatcher::add(const std::string& rule) //{
{
    __RuleState state = __RuleState::BEGIN;
    size_t start = 0;
    for(int i=0;i<rule.size(); i++) {
        char c = rule[i];
        switch(state) {
            case BEGIN:
                if(c == '@') {state = F_AT; break;}
                if(c == '|') {state = F_S;  break;}
                start = 0;
                goto OUTLOOP;
            case F_AT:
                if(c != '@') {return false;}
                state = FS_AT;
                break;
            case FS_AT:
                if(c != '|') {
                    start = i;
                    goto OUTLOOP;
                }
                state = FS_AT_T_S;
                break;
            case FS_AT_T_S:
                if(c != '|') {
                    start = i;
                } else {
                    state = FS_AT_TF_S;
                    start = i + 1;
                }
                goto OUTLOOP;
            case F_S:
                if(c != '|') {
                    start = i;
                } else {
                    start = i + 1;
                    state = FS_S;
                }
                goto OUTLOOP;
            default:
                return false;
        }
    }

OUTLOOP:
    bool has_schema = true;
    std::string uri(rule.c_str() + start, rule.c_str() + rule.size());
    if(uri.find('*') != std::string::npos) {
        std::string new_uri;
        for(auto c: uri) {
            if(c != '*') new_uri.push_back(c);
        }
        uri = new_uri;
    }
    if(uri.find("://") == std::string::npos) {
        has_schema = false;
        uri = "http://" + uri;
    }
    __URL__ parsed_url = parse_url(uri);
    auto schema = parsed_url.m_schema;
    auto host   = parsed_url.m_host;
    int  port   = std::atoi(parsed_url.m_port.c_str());

    if(has_schema && schema_port.find(schema) != schema_port.end())
        port = schema_port[schema];
    if(port == 0) port = -1;

    if(host.size() < 2) {return false;}
    if(host[0] == '.') {
        host.erase(0, 1);
        if(state == BEGIN) state = FS_S;      // TODO
        if(state == FS_AT) state = FS_AT_TF_S;
    }
    if(host.back() == '.') host.erase(host.size() - 1);

    auto vvv = break_string_by_dot(host);

    switch(state) {
        case BEGIN:
        case FS_S:
            this->add_proxy(vvv, port, true);
            break;
        case F_S:
            this->add_proxy(vvv, port, false);
            break;
        case FS_AT:
        case FS_AT_TF_S:
            this->add_exception(vvv, port, true);
            break;
        case FS_AT_T_S:
            this->add_exception(vvv, port, false);
            break;
        default:
            return false;
    }

    return true;
} //}
void ProxyRuleMatcher::add_proxy(const std::vector<std::string>& domain, int port, bool reversal) //{
{
    this->m_proxy.add(domain, port, reversal);
} //}
void ProxyRuleMatcher::add_exception(const std::vector<std::string>& domain, int port, bool reversal) //{
{
    this->m_exception.add(domain, port, reversal);
} //}

std::vector<std::string> ProxyRuleMatcher::Export() //{
{
    auto a = this->m_proxy.Export("");
    auto b = this->m_exception.Export("@@");
    for(auto& x: b) a.push_back(std::move(x));
    return a;
} //}

