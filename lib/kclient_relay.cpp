#include "../include/kclient_relay.h"
#include "../include/kclient_server.h"
#include "../include/ObjectFactory.h"
#include "../include/config.h"


#define DEBUG(all...) __logger->debug(all)


NS_PROXY_CLIENT_START


/** @class RelayConnection
 *  directly proxy a connection through this client */

/** constructor of RelayConnection */
RelayConnection::RelayConnection(Server* kserver, Socks5ServerAbstraction* socks5, 
                                 const std::string& server, uint16_t port, EBStreamAbstraction::UNST server_connection) //{
{
    DEBUG("call %s: relay connection to %s:%d", FUNCNAME, server.c_str(), port);
    this->m_addr = server;
    this->m_port = port;

    this->m_kserver = kserver;
    this->mp_socks5 = socks5;

    this->m_closed = false;

    assert(server_connection != nullptr);
    this->setStreamA(Factory::createUVStreamObject(RELAY_MAX_BUFFER_SIZE, server_connection));
    this->StreamA()->on("connect", server_connect_listener);
}
//}

/** connect to tcp address that specified by socks5 request */
void RelayConnection::connectToAddr() //{
{
    DEBUG("call %s", FUNCNAME);
    uint32_t addr_ipv4;

    if(str_to_ip4(this->m_addr.c_str(), &addr_ipv4)) {
        addr_ipv4 = k_ntohl(addr_ipv4);
        this->StreamA()->connectTo(addr_ipv4, this->m_port);
    } else {
        this->StreamA()->connectTo(this->m_addr, this->m_port);
    }
} //}
/** [static] */
void RelayConnection::server_connect_listener(EventEmitter* em, const std::string& event, EventArgs::Base* aaa) //{
{
    assert(event == "connect");
    EBStreamObject* _streamobj         = dynamic_cast<decltype(_streamobj)>(em); assert(_streamobj);
    RelayConnection* _this             = dynamic_cast<decltype(_this)>(static_cast<StreamRelay*>(_streamobj->fetchPtr())); 
    assert(_this);
    EBStreamObject::ConnectArgs *args  = dynamic_cast<decltype(args)>(aaa);  assert(args);

    assert(_this->mp_socks5 != nullptr);
    auto pp = _this->mp_socks5;
    _this->mp_socks5 = nullptr;
    pp->netAccept();
} //}

void RelayConnection::getStream(EBStreamAbstraction::UNST connection) //{
{
    DEBUG("call %s", FUNCNAME);
    this->setStreamB(Factory::createUVStreamObject(RELAY_MAX_BUFFER_SIZE, connection));
} //}
/** transfer tcp connection from Socks5Auth object to this object */
void RelayConnection::run(Socks5ServerAbstraction* socks5) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->mp_socks5 == nullptr);
    this->getStream(socks5->transferStream());
    socks5->close();
    this->start_relay();
} //}

void RelayConnection::__close() //{
{
    decltype(this->mp_socks5) pp = nullptr;
    if(this->mp_socks5 != nullptr) {
        pp = this->mp_socks5;
        this->mp_socks5 = nullptr;
    }

    this->close();

    if(pp) pp->netReject();
} //}
/** close this object */
void RelayConnection::close() //{
{
    DEBUG("call %s = (this=0x%lx)", FUNCNAME, (long)this);
    assert(this->m_closed == false);
    this->m_closed = true;

    this->m_kserver->remove_socks5_handler(this);
} //}

RelayConnection::~RelayConnection() {}


NS_PROXY_CLIENT_END

