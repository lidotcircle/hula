#include "../include/kclient_clientproxy2.h"
#include "../include/ObjectFactory.hpp"


NS_PROXY_CLIENT_START

/** @class ClientConnection
 *  proxy a single socks5 connection */

/** constructor of ClientConnection2 */
ClientConnection2::ClientConnection2(Server* kserver, ProxyMultiplexerAbstraction2* mproxy,
                                     const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);

    this->mp_proxy = mproxy;
    this->mp_kserver = kserver;

    this->m_socks5 = socks5;
    this->m_closed = false;

    this->m_addr = addr;
    this->m_port = port;
} //}

struct write_callback_data: public CallbackPointer {
    ClientConnection2* _this;
    write_callback_data(ClientConnection2* _this): _this(_this) {}
};

/** socks5 object complete its task and transfer stream of client to this object */
void ClientConnection2::run(Socks5ServerAbstraction* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->StreamA() != nullptr);
    assert(this->StreamB() == nullptr);
    assert(this->m_socks5 == nullptr);

    this->getStream(socks5->transferStream());
    this->start_relay();
} //}
void ClientConnection2::getStream(void* stream) //{
{
    __logger->debug("call %s", FUNCNAME);
    this->setStreamB(Factory::createUVStreamObject(RELAY_MAX_BUFFER_SIZE, stream));
} //}

/** close() */
void ClientConnection2::close() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_closed == false);
    this->m_closed = true;

    this->mp_proxy->remove_clientConnection(this);
} //}

struct __connect_callback_state: public CallbackPointer {
    ClientConnection2* _this;
    __connect_callback_state(ClientConnection2* _this): _this(_this) {}
};
/** connect to @server:port */
void ClientConnection2::connectToAddr() //{
{
    __logger->debug("call %s", FUNCNAME);

    if(this->mp_proxy->uninit()) {
        auto ptr = new __connect_callback_state(this);
        this->add_callback(ptr);
        this->mp_proxy->connectToServer(ClientConnection2::multiplexer_connect_callback, ptr);
    } else {
        this->__connect();
    }
} //}
/** [static] callback for ClientConnection2::connect */
void ClientConnection2::multiplexer_connect_callback(int status, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    __connect_callback_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    ClientConnection2* _this = msg->_this;
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
void ClientConnection2::__connect() //{
{
    __logger->debug("call %s", FUNCNAME);
    if(!this->mp_proxy->connected()) {
        this->m_socks5->netReject();
        this->m_socks5 = nullptr;
        return;
    };
    EBStreamObject* k = Factory::createKProxyMultiplexerStreamObject(PROXY_MAX_BUFFER_SIZE, this->mp_proxy);
    assert(k != nullptr);
    this->setStreamA(k);
    this->StreamA()->connectTo(this->m_addr, this->m_port);
} //}


NS_PROXY_CLIENT_END

