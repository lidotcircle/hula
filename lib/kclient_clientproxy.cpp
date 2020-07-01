#include "../include/kclient_clientproxy.h"


NS_PROXY_CLIENT_START

/** class ClientConnection
 * proxy a single socks5 connection */
//                class ClientConnection                      //{
/** constructor of ClientConnection */
ClientConnection::ClientConnection(Server* kserver, uv_loop_t* loop, 
                                   ConnectionProxy* mproxy,
                                   const std::string& addr, uint16_t port, Socks5Auth* socks5):
    mp_kserver(kserver), mp_loop(loop), mp_proxy(mproxy), m_server(addr), m_port(port), m_socks5(socks5), m_proxy_write_callbacks() //{
{
    __logger->debug("call %s", FUNCNAME);
    this->mp_kserver->register_object(this);

    this->m_state = __State::INITIAL;

    this->m_in_buffer = 0;
    this->m_out_buffer = 0;

    this->mp_tcp_client = nullptr;
    this->m_client_start_read = false;

    this->m_id = this->mp_proxy->requireAnId(this);
    assert(this->m_id < SINGLE_TSL_MAX_CONNECTION);
} //}

void ClientConnection::__start_relay() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_client_start_read == false);
    uv_read_start((uv_stream_t*)this->mp_tcp_client, malloc_cb, ClientConnection::client_read_cb);
    this->m_client_start_read = true;
} //}
/** [static] callback for uv_read_start in ClientConnection::__start_relay() */
void ClientConnection::client_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    ClientConnection* _this = static_cast<decltype(_this)>(uv_handle_get_data((uv_handle_t*)stream));
    if(nread <= 0) {
        free(buf->base);
        _this->close(true);
        return;
    }

    _this->m_out_buffer += nread;

    ROBuf bufx = ROBuf(buf->base, nread, 0, free);
    __proxyWriteInfo* x = new __proxyWriteInfo{_this, false};
    _this->m_proxy_write_callbacks.insert(x);
    _this->mp_proxy->write(_this->m_id, bufx, ClientConnection::ProxyWriteCallback, x);

    if(_this->m_out_buffer > PROXY_MAX_BUFFER_SIZE) {
        uv_read_stop((uv_stream_t*)_this->mp_tcp_client);
        _this->m_client_start_read = false;
    }
} //}
void ClientConnection::ProxyWriteCallback(bool should_run, int status, ROBuf* buf, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    size_t buf_size = buf->size();
    delete buf;

    __proxyWriteInfo* _data = static_cast<decltype(_data)>(data);
    ClientConnection* _this = _data->_this;
    bool exited = _data->exited;
    delete _data;

    should_run = should_run && !exited;
    if(!should_run) return;

    assert(_this->m_proxy_write_callbacks.find(_data) != _this->m_proxy_write_callbacks.end());
    _this->m_proxy_write_callbacks.erase(_this->m_proxy_write_callbacks.find(_data)); //

    _this->m_out_buffer -= buf_size;

    if(status < 0) {
        _this->close(false);
        return;
    }

    if(_this->m_out_buffer < PROXY_MAX_BUFFER_SIZE && !_this->m_client_start_read) {
        _this->__start_relay();
        return;
    }
} //}

void ClientConnection::PushData(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_state == __State::RUNNING);

    __proxyWriteInfo* x = new __proxyWriteInfo{this, false};
    this->m_proxy_write_callbacks.insert(x);

    uv_buf_t* uv_buf = new uv_buf_t();
    uv_buf->base = buf.__base();
    uv_buf->len  = buf.size();

    uv_write_t* req = new uv_write_t();
    auto ptr = new UVC::ClientConnection$write_to_client_callback$uv_write(this->mp_kserver, x, new ROBuf(buf), uv_buf);
    this->mp_kserver->callback_insert(ptr, this);
    uv_req_set_data((uv_req_t*)req, ptr);

    this->m_in_buffer += buf.size();

    uv_write(req, (uv_stream_t*)this->mp_tcp_client, uv_buf, 1, ClientConnection::write_to_client_callback);
} //}
// static
void ClientConnection::write_to_client_callback(uv_write_t* req, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::ClientConnection$write_to_client_callback$uv_write* m = 
        dynamic_cast<decltype(m)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    assert(m);
    auto pp = m->_server->callback_remove(m);
    ROBuf* rbuf = m->_rbuf;
    uv_buf_t* ubuf = m->_ubuf;
    __proxyWriteInfo* info = m->_info;
    ClientConnection* _this = info->_this;
    bool should_run = (pp != nullptr);
    size_t nwrite = ubuf->len;
    delete m;
    delete ubuf;
    delete rbuf;
    delete req;

    should_run = should_run && !info->exited;
    delete info;

    if(!should_run) return;

    assert(_this == pp);

    _this->m_proxy_write_callbacks.erase(_this->m_proxy_write_callbacks.find(info));
    _this->m_in_buffer -= nwrite;
    // TODO traffic control
} //}

void ClientConnection::accept() //{
{
    __logger->debug("call %s", FUNCNAME);
    if(this->m_socks5 == nullptr) {
        this->mp_proxy->close(ConnectionProxy::CloseReason::CLOSE_OPCODE_ERROR);
        return;
    }
    assert(this->m_state == INITIAL);
    this->m_state = CONNECTING;
    this->m_socks5->send_reply(SOCKS5_REPLY_SUCCEEDED);
} //}
void ClientConnection::reject() //{
{
    __logger->debug("call %s", FUNCNAME);
    if(this->m_socks5 == nullptr) {
        this->mp_proxy->close(ConnectionProxy::CloseReason::CLOSE_OPCODE_ERROR);
        return;
    }
    assert(this->m_state == INITIAL);
    this->m_socks5->send_reply(SOCKS5_REPLY_SERVER_FAILURE);
    this->close(false);
} //}

/** socks5 object complete its task and transfer tcp connection of client to this object */
void ClientConnection::run(uv_tcp_t* client_tcp) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(client_tcp);
    assert(this->mp_tcp_client == nullptr);
    assert(this->m_state == CONNECTING);
    this->m_state = RUNNING;

    assert(this->m_socks5 != nullptr);
    this->m_socks5 = nullptr;
    this->mp_tcp_client = client_tcp;
    uv_handle_set_data((uv_handle_t*)this->mp_tcp_client, this);
    this->__start_relay();
} //}

/** close this object which means deallocating resouces like memory, sockets.
 *  And inform ObjectManager to unregister this object which will invalidate 
 *  callback related with this object */
void ClientConnection::close(bool send_close) //{
{
    __logger->debug("call %s", FUNCNAME);
    auto prev_stat = this->m_state; // FIXME
    this->m_state = __State::ERROR;
    for(auto& x: this->m_proxy_write_callbacks)
        x->exited = true;

    switch(prev_stat) {
        case INITIAL:
        case CONNECTING:
        case RUNNING:
            break;
        case ERROR:
            assert(false);
            break;
    }

    if(this->m_socks5 != nullptr) {
        this->mp_kserver->socks5Remove(this->m_socks5);
        this->m_socks5->close();
        this->m_socks5 = nullptr;
    }

    if(this->m_client_start_read) {
        uv_read_stop((uv_stream_t*)this->mp_tcp_client);
        this->m_client_start_read = false;
    }
    if(this->mp_tcp_client) {
        uv_close((uv_handle_t*)this->mp_tcp_client, delete_closed_handle<decltype(this->mp_tcp_client)>);
        this->mp_tcp_client = nullptr;
    }
    if(send_close)
        this->mp_proxy->close_connection(this->m_id, nullptr, nullptr);

    this->mp_kserver->callback_remove_owner(this);
    this->mp_proxy->remove_connection(this->m_id, this);
} //}

/** connect to @server:port */
void ClientConnection::connect(Socks5Auth* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    if(this->mp_proxy->IsConnected())
        return this->__connect(socks5);

    this->mp_proxy->connect(ClientConnection::connect_callback, new std::tuple<ClientConnection*, Socks5Auth*>(this, socks5));
} //}
/** [static] callback for CLientConnection::connect */
void ClientConnection::connect_callback(bool should_run, int status, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    std::tuple<ClientConnection*, Socks5Auth*>* x = static_cast<decltype(x)>(data);
    ClientConnection* _this;
    Socks5Auth* socks5;
    std::tie(_this, socks5) = *x;
    delete x;

    if(!should_run) return;

    if(_this->mp_proxy->IsConnected() == false) {
        assert(status < 0);
        socks5->send_reply(SOCKS5_REPLY_SERVER_FAILURE);
        return;
    }

    _this->__connect(socks5);
} //}
/** [static] callback for CLientConnection::__connect */
static void __connect_new_connection_callback(bool should_run, int status, ROBuf* buf, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    delete buf;
    if(!should_run) return;
    if(status < 0) {
        ClientConnection* _this = 
            dynamic_cast<decltype(_this)>(static_cast<EventEmitter*>(data));
        _this->reject();
    }
} //}
void ClientConnection::__connect(Socks5Auth* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->mp_proxy->IsConnected());
    this->mp_proxy->new_connection(this->m_id, this->m_server, this->m_port, __connect_new_connection_callback, this); // TODO
} //}
//}

NS_PROXY_CLIENT_END

