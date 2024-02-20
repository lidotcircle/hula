#include "../include/kclient_server.h"
#include "../include/ObjectFactory.h"


#define DEBUG(all...) __logger->debug(all)


NS_PROXY_CLIENT_START

/** @class Server
 *  listen to an tcp address to provide service, and manage resources */

/** constructor of Server */
Server::Server(std::shared_ptr<ClientConfig> config) //{
{
    DEBUG("call %s", FUNCNAME);
    this->m_config = config;
    this->m_closed = false;

    this->bind_addr = this->m_config->BindAddr();
    this->bind_port = this->m_config->BindPort();
} //}

/** implement pure virtual function */
void Server::on_connection(UNST connection) //{
{
    DEBUG("call %s", FUNCNAME);

    if(!connection) {
        __logger->info("bad connection");
        return;
    }

    Socks5ServerAbstraction* auth = Factory::KProxyClient::createSocks5Server(this, this->m_config, connection);
    this->m_socks5.insert(auth);
    auth->start();
} //}

/** dispatch socks5 request from Socks5Auth */
void Server::dispatch_base_on_addr(const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5) //{
{
    DEBUG("call %s", FUNCNAME);
    this->dispatch_proxy(addr, port, socks5); // TODO debug
    return;
    if(this->m_config->AdMatch(addr, port)) {
        socks5->netAccept();
        return;
    }
    if(this->m_config->ProxyMatch(addr, port)) {
        this->dispatch_proxy(addr, port, socks5);
    } else {
        this->dispatch_bypass(addr, port, socks5);
    }
} //}
void Server::dispatch_bypass(const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5) //{
{
    DEBUG("call %s", FUNCNAME);
    RelayAbstraction* relay = Factory::KProxyClient::createRelay(this, socks5, addr, port, this->newUnderlyStream());
    this->m_socks5_handler.insert(relay);
    this->m_auths[socks5] = relay;
    relay->connectToAddr();
} //}
void Server::dispatch_proxy(const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5) //{
{
    DEBUG("call %s = (%s, %d, 0x%lx)", FUNCNAME, addr.c_str(), port, (long)socks5);
    ProxyMultiplexerAbstraction* pp = nullptr;
    std::multimap<uint8_t , ProxyMultiplexerAbstraction*> all__;
    for(auto& m: this->m_proxy) {
        if(!m->full() && m->connected())
            all__.insert(std::make_pair(m->getConnectionNumbers(), m));
    }

    if(all__.size() != 0)
        pp = all__.begin()->second;

    if(pp == nullptr) {
        auto c = this->select_remote_serever();
        if(c == nullptr) {
            socks5->netReject();
            return;
        }
        UNST newcon = this->newUnderlyStream();
        pp = Factory::KProxyClient::createUVTLSMultiplexer(this, c, newcon); // TODO certificate and cipher
        this->m_proxy.insert(pp);
    }

    ClientProxyAbstraction* con = Factory::KProxyClient::createProxy(this, pp, addr, port, socks5);
    this->m_auths[socks5] = con;
    this->m_socks5_handler.insert(con);
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
    DEBUG("call %s", FUNCNAME);
    assert(this->m_socks5.find(socks5) != this->m_socks5.end());

    auto ff = this->m_auths.find(socks5);
    if(ff != this->m_auths.end()) {
        RelayAbstraction*  cr      = dynamic_cast<decltype(cr)>(ff->second);
        ClientProxyAbstraction* cc = dynamic_cast<decltype(cc)>(ff->second);
        if(cr != nullptr)
            cr->run(socks5);
        else if (cc != nullptr)
            cc->run(socks5);
        else
            assert(false && "runtime error");

        this->m_auths.erase(ff);
    } else {
        socks5->close();
    }
} //}

static double calculate_point(double prefer, int failure, int success, int current) //{
{
    double ans = 1;
    if(failure <= 0) failure = 1;
    if(success <= 0) success = 1;
    if(current <= 0) current = 1;
    ans += prefer;
    ans *= (success / failure);
    ans *= (4.0 / current);
    return ans;
} //}
/** select a remote server base on some strategies */
SingleServerInfo* Server::select_remote_serever() //{
{
    DEBUG("call %s", FUNCNAME);
    std::multimap<double, SingleServerInfo*> avails;
    for(auto& x: this->m_config->Servers()) {
        auto point = calculate_point(x.get_prefer(), x.failure_counter(), x.success_counter(), x.connections_counter());
        avails.insert(std::make_pair(point, &x));
    }
    if(avails.size() == 0) {
        __logger->warn("no server avaliable, total = %d", this->m_config->Servers().size());
        return nullptr;
    }

    auto selected = avails.rbegin()->second;
    __logger->info("selecte server: %s at %s:%d", selected->name().c_str(), selected->addr().c_str(), selected->port());
    return selected;
} //}

/** deallocate Socks5ServerAbstraction, Socks5RequestProxy* and ProxyMultiplexerAbstraction */
void Server::remove_socks5(Socks5ServerAbstraction* socks5) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_socks5.find(socks5) != this->m_socks5.end());
    this->m_socks5.erase(this->m_socks5.find(socks5));
    delete socks5;
} //}
void Server::remove_socks5_handler(Socks5RequestProxy* handler) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_socks5_handler.find(handler) != this->m_socks5_handler.end());
    this->m_socks5_handler.erase(this->m_socks5_handler.find(handler));
    if(this->m_auths.find(handler) != this->m_auths.end())
        this->m_auths.erase(this->m_auths.find(handler));
    delete handler;
} //}
void Server::remove_proxy(ProxyMultiplexerAbstraction* proxy) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_proxy.find(proxy) != this->m_proxy.end());
    this->m_proxy.erase(this->m_proxy.find(proxy));
    delete proxy;
} //}

int Server::trylisten() //{ 
{
    DEBUG("call %s", FUNCNAME);
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
    assert(this->m_socks5.find(socks5) != this->m_socks5.end());
    if (this->m_auths.find(socks5) != this->m_auths.end())
        return this->m_auths[socks5];
    else
        return nullptr;
} //}

/** close */
void Server::close() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_closed == false);
    this->m_closed = true;

    auto copy_proxy = this->m_proxy;
    for(auto& proxy: copy_proxy)
        proxy->close();

    auto copy_relay = this->m_socks5_handler;
    for(auto& relay: copy_relay)
        relay->close();

    auto copy_socks5 = this->m_socks5;
    for(auto& socks5: copy_socks5)
        socks5->close();

    this->release();
    this->m_config.reset();
    return;
} //}

Server::~Server() {}


NS_PROXY_CLIENT_END

