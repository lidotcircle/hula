#include "../include/kclient_clientproxy.h"
#include "../include/ObjectFactory.hpp"


#define DEBUG(all...) __logger->debug(all)


NS_PROXY_CLIENT_START

/** @class ClientConnection
 *  proxy a single socks5 connection */

/** constructor of ClientConnection */
ClientConnection::ClientConnection(Server* kserver, ProxyMultiplexerAbstraction* mproxy,
                                     const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5) //{
{
    DEBUG("call %s", FUNCNAME);

    this->mp_proxy = mproxy;
    this->mp_kserver = kserver;

    this->m_socks5 = socks5;
    this->m_closed = false;

    this->m_addr = addr;
    this->m_port = port;

    this->mp_proxy->register_clientConnection(this);
} //}

struct write_callback_data: public CallbackPointer {
    ClientConnection* _this;
    write_callback_data(ClientConnection* _this): _this(_this) {}
};

/** socks5 object complete its task and transfer stream of client to this object */
void ClientConnection::run(Socks5ServerAbstraction* socks5) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->StreamA() != nullptr);
    assert(this->StreamB() == nullptr);
    assert(this->m_socks5 == nullptr);

    this->getStream(socks5->transferStream());
    this->start_relay();
} //}
void ClientConnection::getStream(void* stream) //{
{
    DEBUG("call %s", FUNCNAME);
    this->setStreamB(Factory::createUVStreamObject(RELAY_MAX_BUFFER_SIZE, stream));
} //}

/** close() */
void ClientConnection::close() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_closed == false);
    this->m_closed = true;

    this->mp_proxy->remove_clientConnection(this);
} //}
void ClientConnection::__close() //{
{
    DEBUG("call %s", FUNCNAME);

    decltype(this->m_socks5) socks5 = nullptr;
    if(this->m_socks5 != nullptr) {
        socks5 = this->m_socks5;
        this->m_socks5 = nullptr;
    }

    this->close();

    if(socks5 != nullptr) socks5->netReject();
} //}

struct __connect_callback_state: public CallbackPointer {
    ClientConnection* _this;
    __connect_callback_state(ClientConnection* _this): _this(_this) {}
};
/** connect to @server:port */
void ClientConnection::connectToAddr() //{
{
    DEBUG("call %s", FUNCNAME);

    if(this->mp_proxy->uninit()) {
        auto ptr = new __connect_callback_state(this);
        this->add_callback(ptr);
        this->mp_proxy->connectToServer(ClientConnection::multiplexer_connect_callback, ptr);
    } else {
        this->__connect();
    }
} //}
/** [static] callback for ClientConnection::connect */
void ClientConnection::multiplexer_connect_callback(int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    __connect_callback_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    ClientConnection* _this = msg->_this;
    bool run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0) {
        assert(_this->m_socks5 != nullptr);
        _this->m_socks5->netReject();
        _this->m_socks5 = nullptr;
        return;
    }

    _this->__connect();
} //}

/** send connect request */
void ClientConnection::__connect() //{
{
    DEBUG("call %s", FUNCNAME);
    if(!this->mp_proxy->connected()) {
        this->m_socks5->netReject();
        this->m_socks5 = nullptr;
        return;
    };
    EBStreamObject* k = Factory::createKProxyMultiplexerStreamObject(PROXY_MAX_BUFFER_SIZE, this->mp_proxy->getProvider());
    assert(k != nullptr);
    this->setStreamA(k);
    this->StreamA()->on("connect", connect_listener);
    this->StreamA()->connectTo(this->m_addr, this->m_port);
} //}
/** [static] */
void ClientConnection::connect_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* arg) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(eventname == "connect");
    EBStreamObject* stream = dynamic_cast<decltype(stream)>(obj);
    assert(stream);
    StreamRelay* relay = static_cast<StreamRelay*>(stream->fetchPtr());
    ClientConnection* _this = dynamic_cast<decltype(_this)>(relay);
    assert(_this);
    assert(_this->m_socks5 != nullptr);
    auto socks5 = _this->m_socks5;
    _this->m_socks5 = nullptr;
    socks5->netAccept();
} //}


NS_PROXY_CLIENT_END

