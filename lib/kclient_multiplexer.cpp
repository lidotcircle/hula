#include "../include/kclient_multiplexer.h"
#include "../include/kclient_server.h"
#include "../include/config.h"


#define DEBUG(all...) __logger->debug(all)


NS_PROXY_CLIENT_START


/** @class ConnectionProxy
 *  multiplex a tls connection */

struct ConnectionProxy_callback_state: public CallbackPointer {
    ConnectionProxy* _this;
    ConnectionProxy_callback_state(decltype(_this) _this): _this(_this) {}
};

/** constructor of ConnectionProxy */
ConnectionProxy::ConnectionProxy(Server* server, SingleServerInfo* server_info) //{
{
    DEBUG("call %s", FUNCNAME);
    this->mp_server = server;

    this->mp_server_info = server_info;
    this->mp_server_info->increase();

    this->m_state = __State::STATE_INITIAL;

    this->m_connect_cb = nullptr;
    this->m_connect_cb_data = nullptr;

    this->m_total_write_to_client_buffer = 0;
    this->m_total_write_to_server_buffer = 0;
} //}

/** implement pure virtual methods */
void ConnectionProxy::read_callback(ROBuf buf, int status) //{
{
    DEBUG("call %s", FUNCNAME);

    if(status < 0) {
        this->close();
        return;
    }

    ROBuf allbuf = this->m_remain + buf;
    this->m_remain = ROBuf();

    switch(this->m_state) {
        case __State::STATE_CONNECTING:
        case __State::STATE_AUTH:
            __logger->warn("%s: server send message first", FUNCNAME);
            this->close();
            break;
        case __State::STATE_WAIT_AUTH_REPLY:
            this->authenticate(allbuf);
            break;
        case __State::STATE_BUILD:
        case __State::STATE_CLOSING:
            this->prm_read_callback(allbuf);
            break;
        default:
            assert(false && "bug");
            break;
    }
} //}
static void dummy_shutdown_callback(int status, void*) {}
void ConnectionProxy::end_signal() //{
{
    DEBUG("call %s", FUNCNAME);
    this->shutdown(dummy_shutdown_callback, nullptr);
    this->close();
} //}

void ConnectionProxy::prm_error_handle() //{
{
    DEBUG("call %s", FUNCNAME);
    this->close();
} //}
void ConnectionProxy::prm_write(ROBuf buf, KProxyMultiplexerStreamProvider::WriteCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    this->_write(buf, cb, data);
} //}
void ConnectionProxy::prm_timeout(KProxyMultiplexerStreamProvider::TimeoutCallback cb, void* data, int ms) //{
{
    DEBUG("call %s", FUNCNAME);
    EBStreamAbstraction* stream_this = static_cast<decltype(stream_this)>(this);
    assert(stream_this->timeout(cb, data, ms));
} //}

using __connect_to_server_callback_state = ConnectionProxy_callback_state;
/** connect to remote server, and call the callback when either connect success or connect fail */
void ConnectionProxy::__connectToServer(ConnectCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_state == __State::STATE_INITIAL);
    this->m_state = __State::STATE_CONNECTING;

    assert(this->m_connect_cb == nullptr);
    assert(this->m_connect_cb_data == nullptr);
    this->m_connect_cb = cb;
    this->m_connect_cb_data = data;

    auto ptr = new __connect_to_server_callback_state(this);
    this->add_callback(ptr);

    uint32_t ipv4_addr; // TODO maybe support IPV6 literal
    EBStreamAbstraction* stream_this = static_cast<EBStreamAbstraction*>(this);
    if(str_to_ip4(this->mp_server_info->addr().c_str(), &ipv4_addr))
        stream_this->connect(ipv4_addr, this->mp_server_info->port(), connect_to_remote_server_callback, ptr);
    else
        stream_this->connect(this->mp_server_info->addr(), this->mp_server_info->port(), connect_to_remote_server_callback, ptr);
} //}
/** [static] callback for connect() in @__connectToServer() */
void ConnectionProxy::connect_to_remote_server_callback(int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    __connect_to_server_callback_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0) {
        _this->mp_server_info->connect_fail();
        _this->close();
        return;
    }

    _this->send_authentication_info();
} //}

using __authentication_write_state = ConnectionProxy_callback_state;
void ConnectionProxy::send_authentication_info() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_state == __State::STATE_CONNECTING);
    this->m_state = __State::STATE_AUTH;

    if (this->mp_server_info->user().size() >= 256 || 
        this->mp_server_info->pass().size() >= 256) {
        __logger->warn("%s: length of username and password should less than 256", FUNCNAME);
        this->close();
        return;
    }

    ROBuf auth_buf = ROBuf(this->mp_server_info->user().size() + this->mp_server_info->pass().size() + 2);
    auth_buf.__base()[0] = (uint8_t)this->mp_server_info->user().size();
    memcpy(auth_buf.__base() + 1, this->mp_server_info->user().c_str(), this->mp_server_info->user().size());
    auth_buf.__base()[this->mp_server_info->user().size() + 1] = (uint8_t)this->mp_server_info->pass().size();
    memcpy(auth_buf.__base() + this->mp_server_info->user().size() + 2, 
            this->mp_server_info->pass().c_str(), this->mp_server_info->pass().size());

    auto ptr = new __authentication_write_state(this);
    this->add_callback(ptr);

    this->_write(auth_buf, ConnectionProxy::on_authentication_write, ptr);
    this->start_read();
} //}
/** [static] */
void ConnectionProxy::on_authentication_write(ROBuf buf, int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    __authentication_write_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    auto _this = msg->_this;
    auto run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0) {
        _this->mp_server_info->connect_fail();
        _this->close();
        return;
    }

    _this->m_state = __State::STATE_WAIT_AUTH_REPLY;
} //}

/** authenticate reply */
void ConnectionProxy::authenticate(ROBuf buf) //{
{
    DEBUG("call %s", FUNCNAME);
    if(buf.size() < 2) {
        this->m_remain = buf;
        return;
    }

    if((uint8_t)buf.base()[0] != 0xFF ||
       (uint8_t)buf.base()[1] != 0x00) {
        __logger->warn("AUTHENTICATION FAIL");
        this->mp_server_info->connect_fail();
        this->close();
        return;
    }

    __logger->info("AUTHENTICATION SUCCESS");
    this->m_state = __State::STATE_BUILD;
    this->m_remain = buf.increaseOffset(2);
    this->m_connect_cb(0, this->m_connect_cb_data);
    this->m_connect_cb = nullptr;
    this->m_connect_cb_data = nullptr;
    this->mp_server_info->connect_success();
    return;
} //}

void ConnectionProxy::connectToServer(ConnectCallback cb, void* data) {this->__connectToServer(cb, data);}

void ConnectionProxy::remove_clientConnection(ClientProxyAbstraction* obj) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_proxyrelays.find(obj) != this->m_proxyrelays.end());
    this->m_proxyrelays.erase(this->m_proxyrelays.find(obj));
    this->mp_server->remove_socks5_handler(obj);
} //}
void ConnectionProxy::register_clientConnection(ClientProxyAbstraction* obj) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_proxyrelays.find(obj) == this->m_proxyrelays.end());
    this->m_proxyrelays.insert(obj);
} //}

uint8_t ConnectionProxy::getConnectionNumbers() {return this->__getConnectionNumbers();}
bool ConnectionProxy::full()      {return this->__full();}
bool ConnectionProxy::connected() {return this->m_state == __State::STATE_BUILD;}
bool ConnectionProxy::uninit()    {return this->m_state == __State::STATE_INITIAL;}

KProxyMultiplexerStreamProvider* ConnectionProxy::getProvider() {return this;}

/** close this object */
void ConnectionProxy::close() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_state != __State::STATE_CLOSED); // FIXME assert false
    this->m_state = __State::STATE_CLOSED;

    auto proxyrelay_copy = this->m_proxyrelays;
    for(auto& x: proxyrelay_copy)
        x->close();

    this->mp_server_info->decrease();
    this->mp_server->remove_proxy(this);
} //}

ConnectionProxy::~ConnectionProxy() //{
{
    DEBUG("call %s", FUNCNAME);
    if(this->m_connect_cb != nullptr) {
        this->m_connect_cb(-1, this->m_connect_cb_data);
        this->m_connect_cb = nullptr;
        this->m_connect_cb_data = nullptr;
    }
} //}

void ConnectionProxy::CreateNewConnection(EBStreamObject* obj, StreamId, const std::string& addr, uint16_t port) //{
{
    __logger->warn("call %s, bad opcode in client", FUNCNAME);
    this->close();
} //}
void ConnectionProxy::CreateConnectionSuccess(StreamId) //{
{
    __logger->warn("call %s, unexpected function call", FUNCNAME);
    this->close();
} //}
void ConnectionProxy::CreateConnectionFail(StreamId, uint8_t reason) //{
{
    __logger->warn("call %s, unexpected function call", FUNCNAME);
    this->close();
} //}

NS_PROXY_CLIENT_END

