#include "../include/kclient_clientproxy.h"


NS_PROXY_CLIENT_START

/** @class ClientConnection
 *  proxy a single socks5 connection */

/** constructor of ClientConnection */
ClientConnection::ClientConnection(Server* kserver, ProxyMultiplexerAbstraction* mproxy,
                                   const std::string& addr, uint16_t port, Socks5ServerAbstraction* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);

    this->mp_proxy = mproxy;
    this->mp_kserver = kserver;
    this->m_closed = false;

    this->m_write_to_client_buffer = 0;
    this->m_write_to_server_buffer = 0;

    this->m_client_start_read = false;
    this->m_server_start_read = false;

    this->m_id = this->mp_proxy->requireAnId(this);
    this->m_socks5 = socks5;

    this->m_addr = addr;
    this->m_port = port;
} //}

void ClientConnection::__start_relay() //{
{
    __logger->debug("call %s", FUNCNAME);
    this->__relay_client_to_server();
    this->__relay_server_to_client();
} //}
void ClientConnection::__relay_client_to_server() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_client_start_read == false);
    this->start_read();
    this->m_client_start_read = true;
} //}
void ClientConnection::__relay_server_to_client() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_server_start_read == false);
    this->startServerRead();
    this->m_server_start_read = true;
} //}
void ClientConnection::__stop_relay_client_to_server() //{
{
    assert(this->m_client_start_read);
    this->stop_read();
    this->m_client_start_read = false;
} //}
void ClientConnection::__stop_relay_server_to_client() //{
{
    assert(this->m_server_start_read);
    this->stopServerRead();
    this->m_server_start_read = false;
} //}

struct write_callback_data: public CallbackPointer {
    ClientConnection* _this;
    write_callback_data(ClientConnection* _this): _this(_this) {}
};
static void write_callback(ROBuf buf, int status, void* data) //{
{
    write_callback_data* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto run   = msg->CanRun();

    if(!run) return;

    if(status < 0)
        _this->close();
} //}
/** implement pure virtual method */
void ClientConnection::read_callback(ROBuf buf, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    if(status < 0) {
        this->close();
        return;
    }
    auto ptr = new write_callback_data(this);
    this->add_callback(ptr);
    this->mp_proxy->write(this->m_id, this, buf, write_callback, ptr);
} //}
void ClientConnection::end_signal() //{
{
    if(this->m_client_end) {
        this->close();
    } else {
        this->sendServerEnd();
        this->m_client_end = true;
        if(this->m_server_end)
            this->close();
    }
} //}

void ClientConnection::sendServerEnd() //{
{
    this->mp_proxy->connectionEnd(this->m_id, this);
} //}
void ClientConnection::startServerRead() //{
{
    this->mp_proxy->sendStartConnectionRead(this->m_id);
} //}
void ClientConnection::stopServerRead() //{
{
    this->mp_proxy->sendStartConnectionRead(this->m_id);
} //}

struct __writecallbackstate: public CallbackPointer {
    ClientConnection* _this;
    inline __writecallbackstate(ClientConnection* _this): _this(_this) {}
};
void ClientConnection::pushData(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);

    auto save_size = this->m_write_to_client_buffer;
    this->m_write_to_client_buffer += buf.size();
    if(this->m_write_to_client_buffer > PROXY_MAX_BUFFER_SIZE &&
       save_size <= PROXY_MAX_BUFFER_SIZE)
        this->__stop_relay_client_to_server();

    auto ptr = new __writecallbackstate(this);
    this->add_callback(ptr);
    this->_write(buf, write_to_client_callback, ptr);
} //}
/** [static] */
void ClientConnection::write_to_client_callback(ROBuf buf, int status, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    __writecallbackstate* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    ClientConnection* _this = msg->_this;
    bool run                = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    _this->m_write_to_client_buffer -= buf.size();
    if(_this->m_write_to_client_buffer + buf.size() > PROXY_MAX_BUFFER_SIZE &&
       _this->m_write_to_client_buffer <= PROXY_MAX_BUFFER_SIZE)
        _this->__relay_server_to_client();
} //}

static void dummy_shutdown_callback(int, void*) {}
/** reciprocal function of end_signal() */
void ClientConnection::serverEnd() //{
{
    if(this->m_server_end) {
        this->close();
    } else {
        this->shutdown(dummy_shutdown_callback, nullptr);
        this->m_client_end = true;
        if(this->m_server_end)
            this->close();
    }
} //}

/** connect callback from ProxyMultiplexer */
void ClientConnection::connectSuccess() //{
{
    __logger->debug("call %s", FUNCNAME);
    if(this->m_socks5 == nullptr && this->m_state == INITIAL) {
        this->mp_proxy->close();
        return;
    }
    this->m_state = CONNECTING;
    this->m_socks5->netAccept();
    this->m_socks5 = nullptr;
} //}
void ClientConnection::connectFail(ConnectResult) //{
{
    __logger->debug("call %s", FUNCNAME);
    if(this->m_socks5 == nullptr && this->m_state == INITIAL) {
        this->mp_proxy->close();
        return;
    }
    this->m_socks5->netReject(); // TODO
    this->m_socks5 = nullptr;
} //}

/** socks5 object complete its task and transfer stream of client to this object */
void ClientConnection::run(Socks5ServerAbstraction* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->hasStreamObject() == false);
    assert(this->m_state == CONNECTING);
    assert(this->m_socks5 == nullptr);

    this->getStream(socks5->transferStream());
    this->__start_relay();
} //}
void ClientConnection::getStream(void* stream) //{
{
    this->regain(stream);
} //}

/** close() */
void ClientConnection::close() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_closed == false);
    this->m_closed = true;

    this->mp_proxy->remove_clientConnection(this->m_id, this);
} //}

struct __connect_callback_state: public CallbackPointer {
    ClientConnection* _this;
    __connect_callback_state(ClientConnection* _this): _this(_this) {}
};
/** connect to @server:port */
void ClientConnection::connectToAddr() //{
{
    __logger->debug("call %s", FUNCNAME);

    if(this->mp_proxy->uninit()) {
        auto ptr = new __connect_callback_state(this);
        this->add_callback(ptr);
        this->mp_proxy->connectToServer(ClientConnection::multiplexer_connect_callback, ptr);
    }

    return this->__connect();
} //}
/** [static] callback for CLientConnection::connect */
void ClientConnection::multiplexer_connect_callback(int status, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    __connect_callback_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    ClientConnection* _this = msg->_this;
    bool run = msg->CanRun();
    delete msg;

    if(!run) return;

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
    __logger->debug("call %s", FUNCNAME);
    if(!this->mp_proxy->connected()) {
        this->m_socks5->netReject();
        this->m_socks5 = nullptr;
        return;
    };
    this->mp_proxy->new_connection(this->m_id, this, this->m_addr, this->m_port, NEW_CONNECTION_TIMEOUT);
} //}


NS_PROXY_CLIENT_END

