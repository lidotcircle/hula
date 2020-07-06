#include "../include/kclient_relay.h"
#include "../include/kclient_server.h"
#include "../include/ObjectFactory.hpp"
#include "../include/config.h"


NS_PROXY_CLIENT_START


/** @class RelayConnection
 *  directly proxy a connection through this client */

/** constructor of RelayConnection */
RelayConnection::RelayConnection(Server* kserver, Socks5ServerAbstraction* socks5, 
                                 const std::string& server, uint16_t port, void* server_connection):
    m_client_drain_listener_reg(), m_server_drain_listener_reg() //{
{
    __logger->debug("call %s: relay connection to %s:%d", FUNCNAME, server.c_str(), port);
    this->m_client_start_read = false;
    this->m_server_start_read = false;

    this->m_addr = server;
    this->m_port = port;

    this->m_kserver = kserver;
    this->mp_socks5 = socks5;

    this->m_closed = false;

    this->mp_client_manager = nullptr;
    this->mp_server_manager = Factory::createStreamObject(RELAY_MAX_BUFFER_SIZE, server_connection);
    this->mp_server_manager->storePtr(this);
    assert(server_connection != nullptr);

    this->m_client_end = false;
    this->m_server_end = false;

}
//}

/** connect to tcp address that specified by socks5 request */
void RelayConnection::connectToAddr() //{
{
    __logger->debug("call %s", FUNCNAME);
    uint32_t addr_ipv4;

    this->register_server_listener();

    if(str_to_ip4(this->m_addr.c_str(), &addr_ipv4)) {
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = addr_ipv4;
        addr.sin_port = this->m_port;
        this->mp_server_manager->connectWith_sockaddr((sockaddr*)&addr);
    } else {
        this->mp_server_manager->connectWith_address(this->m_addr, this->m_port);
    }
} //}

void RelayConnection::register_server_listener() //{
{
    __logger->debug("call %s", FUNCNAME);
    this->mp_server_manager->on("data", server_data_listener);
    this->mp_server_manager->on("end", server_end_listener);
    this->mp_server_manager->on("error", server_error_listener);
    this->mp_server_manager->on("connect", server_connect_listener);
    this->m_server_drain_listener_reg = this->mp_server_manager->on("drain", server_drain_listener);
} //}
void RelayConnection::register_client_listener() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->mp_client_manager != nullptr);
    this->mp_client_manager->on("data", client_data_listener);
    this->mp_client_manager->on("end", client_end_listener);
    this->mp_client_manager->on("error", client_error_listener);
    this->m_client_drain_listener_reg = this->mp_client_manager->on("drain", client_drain_listener);
} //}

#define EVENTARGS EventEmitter*obj, const std::string& event, EventArgs::Base* aaa
#define DOIT(ename, dt) \
                       __logger->debug("call %s", FUNCNAME); \
                        EBStreamObject* _streamobj = dynamic_cast<decltype(_streamobj)>(obj); assert(_streamobj); \
                        RelayConnection* _this     = static_cast<decltype(_this)>(_streamobj->fetchPtr()); assert(_this); \
                        EBStreamObject::dt *args   = dynamic_cast<decltype(args)>(aaa);  assert(args); \
                        assert(event == ename);
void RelayConnection::client_data_listener(EVENTARGS) //{
{
    DOIT("data", DataArgs);
    auto buf = args->_buf;

    /*
    bool set = false;
    if(!_this->m_client_drain_listener_reg.has()) {
        _this->__stop_relay_client_to_server();
        _this->m_client_drain_listener_reg = _this->mp_client_manager->on("drain", client_drain_listener);
        assert(_this->m_client_drain_listener_reg.has());
        set = true;
    } else {
        __logger->error("client 0x%lx: already has drain cb", (long)static_cast<EventEmitter*>(_this->mp_client_manager));
    }
    */

    auto rv = _this->mp_server_manager->write(buf);
    if(rv < 0 && _this->m_client_start_read)
        _this->__stop_relay_client_to_server();

    /*
    _this->mp_client_manager->remove(_this->m_client_drain_listener_reg);
    _this->m_client_drain_listener_reg.clear();
    assert(!_this->m_client_drain_listener_reg.has());
    */
} //}
void RelayConnection::server_data_listener(EVENTARGS) //{
{
    DOIT("data", DataArgs);
    auto buf = args->_buf;

    /*
    bool set = false;
    if(!_this->m_server_drain_listener_reg.has()) {
        _this->__stop_relay_server_to_client();
        _this->m_server_drain_listener_reg = _this->mp_server_manager->on("drain", server_drain_listener);
        assert(_this->m_server_drain_listener_reg.has());
        set = true;
    } else {
        __logger->error("server 0x%lx: already has drain cb", (long)static_cast<EventEmitter*>(_this->mp_server_manager));
    }
    */

    auto rv = _this->mp_client_manager->write(buf);
    if(rv < 0 && _this->m_server_start_read)
        _this->__stop_relay_server_to_client();

    /*
    _this->mp_server_manager->remove(_this->m_server_drain_listener_reg);
    _this->m_server_drain_listener_reg.clear();
    assert(!_this->m_server_drain_listener_reg.has());
    */
} //}

void RelayConnection::client_drain_listener(EVENTARGS) //{
{
    DOIT("drain", DrainArgs);

    /*
    assert(_this->m_client_drain_listener_reg.has());
    _this->mp_client_manager->remove(_this->m_client_drain_listener_reg);
    _this->m_client_drain_listener_reg.clear();
    assert(!_this->m_client_drain_listener_reg.has());
    */
    if(!_this->m_server_start_read)
        _this->__relay_server_to_client();
} //}
void RelayConnection::server_drain_listener(EVENTARGS) //{
{
    DOIT("drain", DrainArgs);

    /*
    assert(_this->m_server_drain_listener_reg.has());
    _this->mp_server_manager->remove(_this->m_server_drain_listener_reg);
    _this->m_server_drain_listener_reg.clear();
    assert(!_this->m_server_drain_listener_reg.has());
    */
    if(!_this->m_client_start_read)
        _this->__relay_client_to_server();
} //}

void RelayConnection::client_end_listener(EVENTARGS) //{
{
    DOIT("end", EndArgs);

    if(_this->m_client_end) {
        _this->close();
    } else {
        _this->mp_server_manager->end();
        _this->m_client_end = true;
        if(_this->m_server_end)
            _this->close();
    }
} //}
void RelayConnection::server_end_listener(EVENTARGS) //{
{
    DOIT("end", EndArgs);

    if(_this->m_server_end) {
        _this->close();
    } else {
        _this->mp_client_manager->end();
        _this->m_server_end = true;
        if(_this->m_client_end)
            _this->close();
    }
} //}

void RelayConnection::client_error_listener(EVENTARGS) //{
{
    DOIT("error", ErrorArgs);

    assert(_this->mp_socks5 == nullptr);

    _this->close();
} //}
void RelayConnection::server_error_listener(EVENTARGS) //{
{
    DOIT("error", ErrorArgs);

    if(_this->mp_socks5 != nullptr) {
        auto pp = _this->mp_socks5;
        _this->mp_socks5 = nullptr;
        pp->netReject();
    }

    _this->close();
} //}

void RelayConnection::server_connect_listener(EVENTARGS) //{
{
    DOIT("connect", ConnectArgs);

    assert(_this->mp_socks5 != nullptr);
    auto pp = _this->mp_socks5;
    _this->mp_socks5 = nullptr;
    pp->netAccept();
} //}
#undef EVENTARGS
#undef DOIT

void RelayConnection::getStream(void* connection) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->mp_client_manager == nullptr);
    this->mp_client_manager = Factory::createStreamObject(RELAY_MAX_BUFFER_SIZE, connection);
    this->mp_client_manager->storePtr(this);
} //}
/** transfer tcp connection from Socks5Auth object to this object */
void RelayConnection::run(Socks5ServerAbstraction* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->mp_socks5 == nullptr);
    this->getStream(socks5->transferStream());
    socks5->close();
    this->register_client_listener();
    this->__start_relay();
} //}

/** start dual direction tcp relay */
void RelayConnection::__start_relay() //{
{
    __logger->debug("call %s", FUNCNAME);
    this->__relay_client_to_server();
    this->__relay_server_to_client();
} //}

/** As name suggested */
void RelayConnection::__relay_client_to_server() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_client_start_read == false);
    this->mp_client_manager->startRead();
    this->m_client_start_read = true;
} //}
void RelayConnection::__relay_server_to_client() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_server_start_read == false);
    this->mp_server_manager->startRead();
    this->m_server_start_read = true;
} //}
void RelayConnection::__stop_relay_client_to_server() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_client_start_read);
    this->mp_client_manager->stopRead();
    this->m_client_start_read = false;
} //}
void RelayConnection::__stop_relay_server_to_client() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_server_start_read);
    this->mp_server_manager->stopRead();
    this->m_server_start_read = false;
} //}

/** close this object */
void RelayConnection::close() //{
{
    __logger->debug("call %s = (this=0x%lx)", FUNCNAME, (long)this);
    assert(this->m_closed == false);
    this->m_closed = true;

    delete this->mp_server_manager;
    if(this->mp_client_manager != nullptr) delete this->mp_client_manager;

    this->m_kserver->remove_socks5_handler(this);
} //}

RelayConnection::~RelayConnection() {}


NS_PROXY_CLIENT_END

