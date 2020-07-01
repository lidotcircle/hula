#include "../include/kclient_server.h"
#include "../include/ObjectFactory.hpp"


NS_PROXY_CLIENT_START

/** @class Server
 *  listen to an tcp address to provide service, and manage resources */

/** constructor of Server */
Server::Server(std::shared_ptr<ClientConfig> config) //{
{
    __logger->debug("call %s", FUNCNAME);
    this->m_config = config;
    this->m_closed = false;

    this->bind_addr = this->m_config->BindAddr();
    this->bind_port = this->m_config->BindPort();
} //}

/** implement pure virtual function */
void Server::on_connection(void* connection) //{
{
    __logger->debug("call %s", FUNCNAME);

    if(connection == nullptr) {
        __logger->info("bad connection");
        return;
    }

    Socks5ServerAbstraction* auth = Factory::KProxyClient::createSocks5Server(this, connection);
    this->m_auths[auth] = nullptr; 
    auth->start();
} //}

/** dispatch socks5 request from Socks5Auth */
void Server::dispatch_base_on_addr(const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
//    this->dispatch_bypass(addr, port, socks5);
    this->dispatch_proxy(addr, port, socks5);
} //}
void Server::dispatch_bypass(const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    RelayAbstraction* relay = Factory::KProxyClient::createRelay(this, socks5, addr, port, nullptr);
    this->m_relay.insert(relay);
    this->m_auths[socks5] = relay;
    relay->connectToAddr();
} //}
void Server::dispatch_proxy(const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5) //{
{
    __logger->debug("call %s = (%s, %d, 0x%lx)", FUNCNAME, addr.c_str(), port, (long)socks5);
    ProxyMultiplexerAbstraction* pp = nullptr;
    for(auto& m: this->m_proxy) {
        if(!m->full() && m->connected()) {
            pp = m;
            break;
        }
    }

    if(pp == nullptr) {
        auto c = this->select_remote_serever();
        if(c == nullptr) {
            socks5->netReject();
            return;
        }
        void* newcon = this->newUnderlyStream();
        pp = Factory::KProxyClient::createMultiplexer(c, newcon);
        this->m_proxy.insert(pp);
    }

    ClientProxyAbstraction* con = Factory::KProxyClient::createProxy(pp, addr, port, socks5);
    this->m_auths[socks5] = con;
    con->connectToAddr();
} //}

/** dispatch a new connection that proxy #socks5 to connect addr:port */
void Server::dispatchSocks5(const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5) //{
{
    this->dispatch_base_on_addr(addr, port, socks5);
} //}
/** transfer tcp connection from Socks5Auth to RelayConnection or Proxy */
void Server::socks5Transfer(Socks5ServerAbstraction* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    auto ff = this->m_auths.find(socks5);
    assert(ff != this->m_auths.end());

    RelayAbstraction*  cr      = dynamic_cast<decltype(cr)> (ff->second);
    ClientProxyAbstraction* cc = dynamic_cast<decltype(cc)>(ff->second);
    if(cr != nullptr)
        cr->run(socks5);
    else if (cc != nullptr)
        cc->run(socks5);
    else
        assert(false && "runtime error");

    this->m_auths.erase(ff);
} //}

/** select a remote server base on some strategies */
SingleServerInfo* Server::select_remote_serever() //{
{
    __logger->debug("call %s", FUNCNAME);
    for(auto& x: this->m_config->Servers())
        return &x;
    return nullptr;
} //}

/** deallocate Socks5ServerAbstraction, RelayAbstraction and ProxyMultiplexerAbstraction */
void Server::remove_socks5(Socks5ServerAbstraction* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_auths.find(socks5) != this->m_auths.end());
    this->m_auths.erase(this->m_auths.find(socks5));
    delete socks5;
} //}
void Server::remove_relay(RelayAbstraction* relay) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_relay.find(relay) != this->m_relay.end());
    this->m_relay.erase(this->m_relay.find(relay));
    delete relay;
} //}
void Server::remove_proxy(ProxyMultiplexerAbstraction* proxy) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_proxy.find(proxy) != this->m_proxy.end());
    this->m_proxy.erase(this->m_proxy.find(proxy));
    delete proxy;
} //}

int Server::trylisten() //{ 
{
    __logger->debug("call %s", FUNCNAME);
    sockaddr_in addr;

    uint32_t network_order_addr = k_htonl(this->bind_addr);

    ip4_addr(ip4_to_str(network_order_addr), this->bind_port, &addr);
    if(!this->bind((struct sockaddr*)&addr)) {
        logger->error("bind error %s:%d", ip4_to_str(network_order_addr), this->bind_port);
        return -1;
    }
    if(!this->listen()) {
        logger->error("listen error %s:%d", ip4_to_str(network_order_addr), this->bind_port);
        return -1;
    }
    logger->debug("listen at %s:%d", ip4_to_str(network_order_addr), this->bind_port);
    return 0;
} //}

Socks5RequestProxy* Server::getSock5ProxyObject(Socks5ServerAbstraction* socks5) //{
{
    assert(this->m_auths.find(socks5) != this->m_auths.end());
    return this->m_auths[socks5];
} //}

/** close */
void Server::close() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_closed == false);
    this->m_closed = true;

    auto copy_relay = this->m_relay;
    for(auto& relay: copy_relay)
        relay->close();

    auto copy_proxy = this->m_proxy;
    for(auto& proxy: copy_proxy)
        proxy->close();

    auto copy_auth = this->m_auths;
    for(auto& auth: copy_auth)
        auth.first->close();

    return;
} //}

Server::~Server() {}


NS_PROXY_CLIENT_END

