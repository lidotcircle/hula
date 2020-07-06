#pragma once


#include <map>
#include <string>
#include <vector>
#include <set>

extern std::map<std::string, int> schema_port;
extern std::map<int, std::string> port_schema;


class DomainMatcher {
    private:
        std::map<std::string, DomainMatcher*> m_children;
        std::set<int> m_ports;
        bool m_matcher_here;

        bool __match(const std::vector<std::string>& domain, int port, int n);
        void __add  (const std::vector<std::string>& domain, int port, int n);

        void __export(const std::string& prefix, bool reversal, 
                      std::vector<std::string>& _history, std::vector<std::string>& _exports);

    public:
        DomainMatcher();
        ~DomainMatcher();

        bool match(const std::vector<std::string>& domain, int port);
        void add  (const std::vector<std::string>& domain, int port);
        std::vector<std::string> Export(const std::string& prefix, bool reversal = false);
};


class __ProxyRuleMatcher {
    private:
        DomainMatcher m_reversal;
        DomainMatcher m_forward;

    public:
        __ProxyRuleMatcher();
        bool match(const std::vector<std::string>& domain, int port);
        void add  (const std::vector<std::string>& domain, int port, bool reversal = false);
        std::vector<std::string> Export(const std::string& prefix);
};


class ProxyRuleMatcher {
    private:
        __ProxyRuleMatcher m_proxy;
        __ProxyRuleMatcher m_exception;

    public:
        ProxyRuleMatcher();

        bool __match(const std::vector<std::string>& domain, int port);
        bool match(const std::string& addr, int port);
        bool add  (const std::string& rule);
        void add_proxy    (const std::vector<std::string>& domain, int port, bool reversal = false);
        void add_exception(const std::vector<std::string>& domain, int port, bool reversal = false);
        std::vector<std::string> Export();
};

