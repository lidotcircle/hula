#include "../include/kclient_multipler.h"


NS_PROXY_CLIENT_START


/** class ConnectionProxy
 * multiplex a tls connection */
//                class ConnectionProxy                      //{
/** constructor of ConnectionProxy */
ConnectionProxy::ConnectionProxy(uv_loop_t* loop, Server* server, SingleServerInfo* server_info) //{
{
    __logger->debug("call %s", FUNCNAME);
    this->mp_server = server;
    this->mp_server->register_object(this);

    this->mp_loop = loop;
    this->mp_server_info = server_info;

    this->m_out_buffer = 0;
    this->m_remain_raw = ROBuf();

    this->m_state = __State::STATE_INITIAL;

    this->mp_connection = nullptr;
    this->m_connection_read = false;

    this->m_connect_cb = nullptr;
    this->m_connect_cb_data = nullptr;
} //}

/** If has remaining valid id return it otherwise return an invalid id */
uint8_t ConnectionProxy::get_id() //{
{
    __logger->debug("call %s", FUNCNAME);
    for(uint8_t i=0; i<SINGLE_TSL_MAX_CONNECTION; i++) {
        if(this->m_map.find(i) == this->m_map.end())
            return i;
    }
    return SINGLE_TSL_MAX_CONNECTION;
} //}

/** connect to remote server, and call the callback when either connect success or connect fail 
 *  wrapper of @ConnectionProxy::connect_to_remote_server() */
void ConnectionProxy::connect(ConnectCallback cb, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_connect_cb == nullptr);
    assert(this->m_connect_cb_data == nullptr);
    this->m_connect_cb = cb;
    this->m_connect_cb_data = data;
    this->connect_to_remote_server();
} //}
void ConnectionProxy::connect_to_remote_server() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_state == __State::STATE_INITIAL);
    this->m_state = __State::STATE_GETDNS;

    this->mp_server_info->increase();
    this->mp_connection = new uv_tcp_t();
    uv_tcp_init(this->mp_loop, this->mp_connection);
    uv_handle_set_data((uv_handle_t*)this->mp_connection, this);

    assert(this->m_connect_cb != nullptr);
    assert(this->m_connect_cb_data != nullptr);

    uint32_t ipv4_addr; // TODO maybe support IPV6
    if(str_to_ip4(this->mp_server_info->addr().c_str(), &ipv4_addr)) {
        struct addrinfo info;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = k_ntohs(this->mp_server_info->port()); // FIXME
        addr.sin_addr.s_addr = k_ntohl(ipv4_addr);
        info.ai_family = AF_INET;
        info.ai_addrlen = sizeof(sockaddr_in); // FIXME ??
        info.ai_canonname = nullptr;
        info.ai_next = nullptr;
        info.ai_flags = 0;
        info.ai_addr = (sockaddr*)&addr;

        uv_getaddrinfo_t req;
        auto ptr = new UVC::ConnectionProxy$connect_to_remote_server$uv_getaddrinfo(
                this->mp_server, this, false);
        uv_req_set_data((uv_req_t*)&req, ptr);
        this->mp_server->callback_insert(ptr, this);

        ConnectionProxy::connect_remote_getaddrinfo_cb(&req, 0, &info);
    } else {
        struct addrinfo hints;
        hints.ai_family = AF_INET;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = 0;

        uv_getaddrinfo_t* p_req = new uv_getaddrinfo_t();
        auto ptr = new UVC::ConnectionProxy$connect_to_remote_server$uv_getaddrinfo(
                this->mp_server, this, true);
        uv_req_set_data((uv_req_t*)p_req, ptr);
        this->mp_server->callback_insert(ptr, this);

        uv_getaddrinfo(this->mp_loop, p_req, 
                       ConnectionProxy::connect_remote_getaddrinfo_cb, 
                       this->mp_server_info->addr().c_str(), "80", &hints);
    }
} //}

/** [static] callback for uv_getaddrinfo() in @connect_to_remote_server() */
void ConnectionProxy::connect_remote_getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) //{
{
    __logger->debug("call %s", FUNCNAME);
    struct addrinfo *a;
    struct sockaddr_in* m;

    UVC::ConnectionProxy$connect_to_remote_server$uv_getaddrinfo* msg =
        dynamic_cast<decltype(msg)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    auto pp = msg->_server->callback_remove(msg);
    bool clean = msg->_clean;
    ConnectionProxy* _this = msg->_this;
    bool should_run = (pp != nullptr);

    if(clean) delete req;
    delete msg;

    if(!should_run) {
        /* if(clean) */ uv_freeaddrinfo(res);
        _this->m_connect_cb(false, -1, _this->m_connect_cb_data);
        _this->m_connect_cb = nullptr;
        _this->m_connect_cb_data = nullptr;
        return;
    }

    assert(pp == _this);

    if(status < 0) {
        __logger->warn("%s: dns query fail", FUNCNAME);
        if(clean) uv_freeaddrinfo(res);
        _this->m_state = __State::STATE_ERROR;
        _this->m_connect_cb(true, -1, _this->m_connect_cb_data);
        _this->m_connect_cb = nullptr;
        _this->m_connect_cb_data = nullptr;
        _this->close(ConnectionProxy::CLOSE_REMOTE_SERVER_DNS);
        return;
    }
    for(a = res; a != nullptr; a = a->ai_next) {
        if(sizeof(struct sockaddr_in) != a->ai_addrlen) {
            __logger->warn("%s: query dns get an address that isn't ipv4 address", FUNCNAME);
            continue;
        } else break;
    }
    if(a == nullptr) {
        __logger->warn("%s: query dns doesn't get an ipv4 address", FUNCNAME);
        if(clean) uv_freeaddrinfo(res);
        _this->m_state = __State::STATE_ERROR;
        _this->m_connect_cb(true, -1, _this->m_connect_cb_data);
        _this->m_connect_cb = nullptr;
        _this->m_connect_cb_data = nullptr;
        _this->close(ConnectionProxy::CLOSE_REMOTE_SERVER_DNS);
        return;
    }
    m = (struct sockaddr_in*)a->ai_addr; // FIXME ipv6
    m->sin_port = _this->mp_server_info->port();
    _this->connect_to_with_sockaddr((sockaddr*)m);
    if(clean) uv_freeaddrinfo(res);
} //}

/** connect to remote server by sockaddr* */
void ConnectionProxy::connect_to_with_sockaddr(sockaddr* sock) //{
{
    __logger->debug("call %s", FUNCNAME);
    uv_connect_t* req = new uv_connect_t();
    auto ptr = new UVC::ConnectionProxy$connect_to_with_sockaddr$uv_tcp_connect(this->mp_server, this);
    uv_req_set_data((uv_req_t*)req, ptr);
    this->mp_server->callback_insert(ptr, this);

    assert(this->m_state == __State::STATE_GETDNS); // FIXME fail
    this->m_state = __State::STATE_CONNECTING;

    uv_tcp_connect(req, this->mp_connection, sock, ConnectionProxy::connect_remote_tcp_connect_cb);
} //}

/** [static] callback for uv_connect(0 in @connect_to_with_sockaddr() */
void ConnectionProxy::connect_remote_tcp_connect_cb(uv_connect_t* req, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::ConnectionProxy$connect_to_with_sockaddr$uv_tcp_connect* ptr =
        dynamic_cast<decltype(ptr)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    assert(ptr);
    Server* server = ptr->_server;
    auto pp = server->callback_remove(ptr);
    ConnectionProxy* _this = ptr->_this;
    bool should_run = (pp != nullptr);
    delete req;
    delete ptr;

    if(!should_run) {
        _this->m_connect_cb(false, -1, _this->m_connect_cb_data);
        _this->m_connect_cb = nullptr;
        _this->m_connect_cb_data = nullptr;
        return;
    }

    assert(pp == _this);
    assert(_this->m_state == __State::STATE_CONNECTING);

    if(status < 0) {
        __logger->warn("ConnectionProxy: connect to remote server fail");
        _this->m_connect_cb(true, status, _this->m_connect_cb_data);
        _this->m_connect_cb = nullptr;
        _this->m_connect_cb_data = nullptr;
        _this->close(ConnectionProxy::CLOSE_REMOTE_SERVER_CONNECT_ERROR);
        return;
    }

    _this->tsl_handshake();
} //}

/** routine to complete tls handshake */
void ConnectionProxy::tsl_handshake() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_state == __State::STATE_CONNECTING);
    this->m_state = __State::STATE_TSL;
    this->client_authenticate();
} //}
/** routine to complete user authentication */
void ConnectionProxy::client_authenticate() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_state == __State::STATE_TSL);
    this->m_state = __State::STATE_AUTH;

    if (this->mp_server_info->user().size() >= 256 || 
        this->mp_server_info->pass().size() >= 256) {
        __logger->warn("%s: length of username and password should less than 256", FUNCNAME);
        this->m_connect_cb(true, -1, this->m_connect_cb_data);
        this->m_connect_cb = nullptr;
        this->m_connect_cb_data = nullptr;
        this->close(CLOSE_AUTHENTICATION_ERROR);
        return;
    }
    ROBuf auth_buf = ROBuf(this->mp_server_info->user().size() + this->mp_server_info->pass().size() + 2);
    auth_buf.__base()[0] = (uint8_t)this->mp_server_info->user().size();
    memcpy(auth_buf.__base() + 1, this->mp_server_info->user().c_str(), this->mp_server_info->user().size());
    auth_buf.__base()[this->mp_server_info->user().size() + 1] = (uint8_t)this->mp_server_info->pass().size();
    memcpy(auth_buf.__base() + this->mp_server_info->user().size() + 2, 
            this->mp_server_info->pass().c_str(), this->mp_server_info->pass().size());

    this->_write(auth_buf, ConnectionProxy::on_authentication_write, this);
} //}

/** [static] callback for @_write() in @client_authenticate() */
void ConnectionProxy::on_authentication_write(bool should_run, int status, ROBuf* buf, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    ConnectionProxy* _this = dynamic_cast<decltype(_this)>(static_cast<EventEmitter*>(data));
    assert(_this);
    delete buf;

    if(!should_run || status < 0) {
        _this->m_connect_cb(should_run, status, _this->m_connect_cb_data);
        _this->m_connect_cb = nullptr;
        _this->m_connect_cb_data = nullptr;
        return;
    }

    assert(_this->m_state == __State::STATE_AUTH);
    _this->m_state = __State::STATE_WAIT_AUTH_REPLY;

    uv_handle_set_data((uv_handle_t*)_this->mp_connection, _this);
    assert(_this->m_connection_read == false);
    uv_read_start((uv_stream_t*)_this->mp_connection, malloc_cb, ConnectionProxy::uv_stream_read_after_send_auth_callback);
    _this->m_connection_read = true;
} //}

/** [static] callback for uv_read, this function will call @authenticate_with_remains() when get a valid reply */
void ConnectionProxy::uv_stream_read_after_send_auth_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    ConnectionProxy* _this = 
        dynamic_cast<decltype(_this)>(static_cast<EventEmitter*>(uv_handle_get_data((uv_handle_t*)stream)));
    assert(_this);

    if(nread <= 0) {
        _this->m_connect_cb(true, -1, _this->m_connect_cb_data);
        _this->m_connect_cb = nullptr;
        _this->m_connect_cb_data = nullptr;
        _this->close(CLOSE_READ_ERROR);
        free(buf->base);
        return;
    }

    ROBuf bufx = ROBuf(buf->base, nread, 0, free);
    _this->m_remain_raw = _this->m_remain_raw + bufx;

    if(_this->m_remain_raw.size() < 2) return;

    switch(_this->m_state) {
        case __State::STATE_WAIT_AUTH_REPLY:
            _this->authenticate_with_remains();
            break;
        case __State::STATE_ERROR:
            _this->m_connect_cb(true, -1, _this->m_connect_cb_data);
            _this->m_connect_cb = nullptr;
            _this->m_connect_cb_data = nullptr;
            _this->close(CLOSE_PACKET_ERROR);
            break;
        case __State::STATE_BUILD:
        case __State::STATE_TSL:
        case __State::STATE_AUTH:
        case __State::STATE_INITIAL:
        case __State::STATE_GETDNS:
        case __State::STATE_CONNECTING:
        case __State::STATE_CLOSING:
        case __State::STATE_CLOSED:
        default:
            assert(false && "It isn't a correct time to call ConnectionProxy::uv_stream_read_after_send_auth_callback()");
            break;
    }

    uv_read_stop((uv_stream_t*)_this->mp_connection);
    uv_handle_set_data((uv_handle_t*)_this->mp_connection, _this);
    uv_read_start((uv_stream_t*)_this->mp_connection, malloc_cb, ConnectionProxy::uv_stream_read_packet);
} //}

/** [static] callback for uv_read when user authentication has completed 
 *  which will call @dispatch_data_encrypted() */
void ConnectionProxy::uv_stream_read_packet(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    ConnectionProxy* _this = dynamic_cast<decltype(_this)>(static_cast<EventEmitter*>(uv_handle_get_data((uv_handle_t*)stream)));
    assert(_this);

    if(nread == 0) return;

    if(nread < 0) {
        _this->close(CLOSE_READ_ERROR);
        free(buf->base);
        return;
    }

    ROBuf bufx = ROBuf(buf->base, nread, 0, free);

    switch(_this->m_state) {
        case __State::STATE_ERROR:
            _this->close(CLOSE_PACKET_ERROR);
            break;
        case __State::STATE_BUILD:
            _this->dispatch_data_encrypted(bufx);
            break;
        case __State::STATE_TSL:
        case __State::STATE_AUTH:
        case __State::STATE_INITIAL:
        case __State::STATE_GETDNS:
        case __State::STATE_CONNECTING:
        case __State::STATE_CLOSING:
        case __State::STATE_CLOSED:
        case __State::STATE_WAIT_AUTH_REPLY:
        default:
            assert(false && "It isn't a correct time to call ConnectionProxy::uv_stream_read_packet()");
            break;
    }
} //}

/** dispatch encrypted data */
void ConnectionProxy::dispatch_data_encrypted(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    this->dispatch_data(buf);
} //}
/** dispatch unencrypted data */
void ConnectionProxy::dispatch_data(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    std::tuple<bool, std::vector<std::tuple<ROBuf, PACKET_OPCODE, uint8_t>>, ROBuf> mm = 
        decode_all_packet(this->m_remain_raw, buf);
    bool noerror;
    std::vector<std::tuple<ROBuf, PACKET_OPCODE, uint8_t>> packets;
    std::tie(noerror, packets, this->m_remain_raw) = mm;
    if(noerror == false) {
        this->close(CLOSE_PACKET_ERROR);
        return;
    }

    for(auto& p: packets) {
        ROBuf frame;
        PACKET_OPCODE opcode;
        uint8_t id;
        std::tie(frame, opcode, id) = p;

        if(this->m_map.find(id) == this->m_map.end()) {
            this->close(CLOSE_ID_ERROR);
            return;
        }

        ClientConnection* cc = this->m_map[id];

        switch (opcode) {
            case PACKET_OP_REG:
                cc->PushData(frame);
                break;
            case PACKET_OP_CLOSE:
                cc->close(false);
                break;
            case PACKET_OP_CONNECT:
                if(this->m_wait_new_connection.find(id) == this->m_wait_new_connection.end()) {
                    __logger->warn("ConnectionProxy recieves a packet to ClientConnection which doesn't exists. CONNECT");
                    this->close_connection(id, nullptr, nullptr);
                    cc->close(false);
                } else {
                    assert(this->m_map.find(id) != this->m_map.end());
                    this->m_wait_new_connection.erase(this->m_wait_new_connection.find(id));
                    this->m_map[id]->accept();
                }
                break;
            case PACKET_OP_REJECT:
                if(this->m_wait_new_connection.find(id) == this->m_wait_new_connection.end()) {
                    __logger->warn("ConnectionProxy recieves a packet to ClientConnection which doesn't exists. REJECT");
                    cc->close(false);
                } else {
                    assert(this->m_map.find(id) != this->m_map.end());
                    this->m_wait_new_connection.erase(this->m_wait_new_connection.find(id));
                    this->m_map[id]->reject();
                }
                break;
            case PACKET_OP_NEW:
            case PACKET_OP_RESERVED:
            default:
                __logger->warn("KProxyClient recieve a packet with unexpected opcode. IGNORE it");
                return;
        }
    }
} //}

/** authenticate base on the reply */
void ConnectionProxy::authenticate_with_remains() //{
{
    __logger->debug("call %s", FUNCNAME);
    ROBuf merge = this->m_remain_raw;
    assert(merge.size() >= 2);

    if((uint8_t)merge.base()[0] != 0xFF ||
       (uint8_t)merge.base()[1] != 0x00) {
        __logger->warn("AUTHENTICATION FAIL");
        this->close(CLOSE_AUTHENTICATION_ERROR);
        this->m_connect_cb(true, -1, this->m_connect_cb_data);
        this->m_connect_cb = nullptr;
        this->m_connect_cb_data = nullptr;
        return;
    }

    __logger->info("AUTHENTICATION SUCCESS");
    this->m_state = __State::STATE_BUILD;
    this->m_remain_raw = merge + 2;
    this->m_connect_cb(true, 0, this->m_connect_cb_data);
    this->m_connect_cb = nullptr;
    this->m_connect_cb_data = nullptr;
    return;
} //}

/** send buffer to remote server */
int ConnectionProxy::_write(ROBuf buf, WriteCallback cb, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->mp_connection != nullptr);

    uv_buf_t* uv_buf = new uv_buf_t();
    uv_buf->base = buf.__base();
    uv_buf->len = buf.size();

    ROBuf* mem_holder = new ROBuf(buf);

    uv_write_t* req = new uv_write_t();
    auto ptr = new UVC::ConnectionProxy$_write$uv_write(this->mp_server, this, cb, data, mem_holder, uv_buf);
    uv_req_set_data((uv_req_t*)req, ptr);
    this->mp_server->callback_insert(ptr, this);

    this->m_out_buffer += buf.size();
    return uv_write(req, (uv_stream_t*)this->mp_connection, uv_buf, 1, ConnectionProxy::_write_callback);
} //}
/** [static] callback for uv_write() in @ConnectionProxy::_write() */
void ConnectionProxy::_write_callback(uv_write_t* req, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::ConnectionProxy$_write$uv_write* msg = 
        dynamic_cast<decltype(msg)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    assert(msg);
    auto _this = msg->_this;
    auto cb = msg->_cb;
    auto data = msg->_data;
    auto uv_buf = msg->_uv_buf;
    auto mem_holder = msg->_mem_holder;
    auto server = msg->_server;
    auto pp = server->callback_remove(msg);
    bool should_run = (pp != nullptr);

    if(should_run) _this->m_out_buffer -= mem_holder->size();

    delete msg;
    delete uv_buf;
    delete req;

    if(cb != nullptr)
        cb(should_run, status, mem_holder, data);
    else
        delete mem_holder;

    if(!should_run) return;

    assert(pp == _this);

    if(status < 0) {
        _this->close(CLOSE_WRITE_ERROR);
        return;
    }
} //}

/** wrapper of @ConnectionProxy::_write() */
int ConnectionProxy::write(uint8_t id, ROBuf buf, WriteCallback cb, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(id < SINGLE_TSL_MAX_CONNECTION);
    ROBuf x = encode_packet_header(PACKET_OPCODE::PACKET_OP_REG, id, buf.size()) + buf;
    return this->_write(x, cb, data);
} //} 

struct new_connection_wrapper_data {
    ConnectionProxy* _this;
    uint8_t m_id;
    ConnectionProxy::WriteCallback m_cb;
    void* m_data;
    bool  m_writecallback_called;
    bool  m_timer_called;
};
/** send a packet which inform remote server to create a new connection to #addr:#port, and
 *  cb will be called when either success or fail */
int ConnectionProxy::new_connection(uint8_t id, 
        const std::string& addr, uint16_t port, 
        WriteCallback cb, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_map.find(id) != this->m_map.end());
    assert(this->m_map[id]->IsRun() == false);

    ROBuf buf = ROBuf(addr.size() + 2);
    memcpy(buf.__base(), addr.c_str(), addr.size());
    *(uint16_t*)(&buf.__base()[addr.size()]) = k_htons(port);
    auto x = encode_packet(PACKET_OP_NEW, id, buf);
    new_connection_wrapper_data* new_data = new new_connection_wrapper_data{this, id, cb, data, false, false};
    int ret = this->_write(x, ConnectionProxy::new_connection_callback_wrapper, new_data);
    this->m_wait_new_connection.insert(id);

    uv_timer_t* timer = new uv_timer_t();
    uv_timer_init(this->mp_loop, timer);
    auto ptr = new UVC::ConnectionProxy$new_connection$uv_timer_start(this->mp_server, this, new_data);
    uv_handle_set_data((uv_handle_t*)timer, ptr);
    this->mp_server->callback_insert(ptr, this);
    uv_timer_start(timer, ConnectionProxy::new_connection_timer_callback, NEW_CONNECTION_TIMEOUT, 0);

    return ret;
} //}

/** [static] callback for @ConnectionProxy::_write() in @ConnectionProxy::new_connection() */
void ConnectionProxy::new_connection_callback_wrapper(bool should_run, int status, ROBuf* buf, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    new_connection_wrapper_data* kdata = static_cast<decltype(kdata)>(data);
    ConnectionProxy* _this = kdata->_this;
    uint8_t id = kdata->m_id;
    WriteCallback cb = kdata->m_cb;
    void* cb_data = kdata->m_data;
    bool timer_called = kdata->m_timer_called;
    if(timer_called)
        delete kdata;
    else
        kdata->m_writecallback_called = true;

    if(!timer_called) {
        cb(should_run, status, buf, cb_data);
    } else {
        delete buf;
    }
} //}
/** [static] callback for uv_timer_start() in @ConnectionProxy::new_connection() */
void ConnectionProxy::new_connection_timer_callback(uv_timer_t* timer) //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::ConnectionProxy$new_connection$uv_timer_start* msg = 
        dynamic_cast<decltype(msg)>(static_cast<UVC::UVCBaseClient*>(uv_handle_get_data((uv_handle_t*)timer)));
    assert(msg);
    auto pp = msg->_server->callback_remove(msg);
    ConnectionProxy* _this = msg->_this;
    new_connection_wrapper_data* _data = static_cast<decltype(_data)>(msg->_data);
    bool should_run = (pp != nullptr);
    uv_timer_stop(timer);
    uv_close((uv_handle_t*)timer, delete_closed_handle<decltype(timer)>);
    delete msg;

    bool writecallback_called = _data->m_writecallback_called;
    WriteCallback cb = _data->m_cb;
    void* cb_data = _data->m_data;
    uint8_t id = _data->m_id;

    if(writecallback_called) {
        delete _data;
    } else {
        _data->m_timer_called = true;
        cb(should_run, -1, new ROBuf(), cb_data);
    }

    if(should_run) {
        assert(pp == _this);
        if(_this->m_wait_new_connection.find(id) != _this->m_wait_new_connection.end()) {
            _this->m_wait_new_connection.erase(_this->m_wait_new_connection.find(id));
        }
    }
} //}

/**
 * send a packet that indicate close connection id of which is #id
 * @param {uint8_t id} the id should be deallocated by @ConnecitonProxy::remove_connection()
 * @param {WriteCallback cb} the callback will be called when either write finish or error raise
 * @param {void* data} data pass to callback function */
int ConnectionProxy::close_connection(uint8_t id, WriteCallback cb, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    auto x = encode_packet(PACKET_OP_CLOSE, id, ROBuf((char*)"close", 5));
    return this->_write(x, cb, data);
} //}

/**
 * deallocate the memory that allocated to this ClientConnection object
 * @param {uint8_t id} the id of the ClientConnection object
 * @param {ClientConnection* obj} the pointer points to the ClientConnection object */
void ConnectionProxy::remove_connection(uint8_t id, ClientConnection* obj) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_map.find(id) != this->m_map.end());
    assert(this->m_map[id] == obj);
    this->m_map.erase(this->m_map.find(id));
    delete obj;
} //}

/** allocate an id to #connection 
 * @precondition this object must own avaliable id, otherwise abort */
uint8_t ConnectionProxy::requireAnId(ClientConnection* connection) //{
{
    __logger->debug("call %s", FUNCNAME);
    uint8_t id = this->get_id();
    assert(id < SINGLE_TSL_MAX_CONNECTION);
    this->m_map[id] = connection;
    return id;
} //}

/** close this object */
void ConnectionProxy::close(CloseReason reason) //{
{
    __logger->debug("call %s", FUNCNAME);
    this->m_state = __State::STATE_CLOSING;

    if(this->m_connection_read) {
        uv_read_stop((uv_stream_t*)this->mp_connection);
        this->m_connection_read = false;
    }
    if(this->mp_connection != nullptr) {
        uv_close((uv_handle_t*)this->mp_connection, delete_closed_handle<decltype(this->mp_connection)>);
        this->mp_connection = nullptr;
    }

    auto mm = this->m_map;
    for(auto& x: mm)
        x.second->close(false);

    this->m_state = __State::STATE_CLOSED;
    this->mp_server->callback_remove_owner(this);
    this->mp_server->remove_proxy(this);
} //}

ConnectionProxy::~ConnectionProxy() //{
{
    __logger->debug("call %s", FUNCNAME);
} //}

//}


NS_PROXY_CLIENT_END

