#include "../include/kclient_multiplexer.h"
#include "../include/kclient_server.h"


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
    __logger->debug("call %s", FUNCNAME);
    this->mp_server = server;

    this->mp_server_info = server_info;

    this->m_state = __State::STATE_INITIAL;

    this->m_connect_cb = nullptr;
    this->m_connect_cb_data = nullptr;

    this->m_total_write_to_client_buffer = 0;
    this->m_total_write_to_server_buffer = 0;
} //}

/** implement pure virtual methods */
void ConnectionProxy::read_callback(ROBuf buf, int status) //{
{
    __logger->debug("call %s", FUNCNAME);

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
            this->dispatch_data(allbuf);
            break;
        default:
            assert(false && "bug");
            break;
    }
} //}
static void dummy_shutdown_callback(int status, void*) {}
void ConnectionProxy::end_signal() //{
{
    this->shutdown(dummy_shutdown_callback, nullptr);
    this->close();
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

using __connect_to_server_callback_state = ConnectionProxy_callback_state;
/** connect to remote server, and call the callback when either connect success or connect fail */
void ConnectionProxy::__connectToServer(ConnectCallback cb, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_state == __State::STATE_INITIAL);
    this->m_state = __State::STATE_CONNECTING;

    assert(this->m_connect_cb == nullptr);
    assert(this->m_connect_cb_data == nullptr);
    this->m_connect_cb = cb;
    this->m_connect_cb_data = data;

    this->mp_server_info->increase();

    auto ptr = new __connect_to_server_callback_state(this);
    this->add_callback(ptr);

    uint32_t ipv4_addr; // TODO maybe support IPV6 literal
    if(str_to_ip4(this->mp_server_info->addr().c_str(), &ipv4_addr))
        this->connect(ipv4_addr, this->mp_server_info->port(), connect_to_remote_server_callback, nullptr);
    else
        this->connect(this->mp_server_info->addr(), this->mp_server_info->port(), connect_to_remote_server_callback, nullptr);
} //}
/** [static] callback for uv_connect(0 in @connect_to_with_sockaddr() */
void ConnectionProxy::connect_to_remote_server_callback(int status, void* data) //{
{
    __connect_to_server_callback_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0) {
        _this->close();
        return;
    }

    _this->send_authentication_info();
} //}

using __authentication_write_state = ConnectionProxy_callback_state;
void ConnectionProxy::send_authentication_info() //{
{
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
} //}
/** [static] */
void ConnectionProxy::on_authentication_write(ROBuf buf, int status, void* data) //{
{
    __authentication_write_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    auto _this = msg->_this;
    auto run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0) {
        _this->close();
        return;
    }

    _this->m_state = __State::STATE_WAIT_AUTH_REPLY;
} //}

/** authenticate reply */
void ConnectionProxy::authenticate(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    if(buf.size() < 2) {
        this->m_remain = buf;
        return;
    }

    if((uint8_t)buf.base()[0] != 0xFF ||
       (uint8_t)buf.base()[1] != 0x00) {
        __logger->warn("AUTHENTICATION FAIL");
        this->close();
        return;
    }

    __logger->info("AUTHENTICATION SUCCESS");
    this->m_state = __State::STATE_BUILD;
    this->m_remain = buf + 2;
    this->m_connect_cb(0, this->m_connect_cb_data);
    this->m_connect_cb = nullptr;
    this->m_connect_cb_data = nullptr;
    return;
} //}

/** dispatch unencrypted data */
void ConnectionProxy::dispatch_data(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    std::tuple<bool, std::vector<std::tuple<ROBuf, PACKET_OPCODE, uint8_t>>, ROBuf> mm = 
        decode_all_packet(this->m_remain, buf);
    bool noerror;
    std::vector<std::tuple<ROBuf, PACKET_OPCODE, uint8_t>> packets;
    std::tie(noerror, packets, this->m_remain) = mm;
    if(noerror == false) {
        this->close();
        return;
    }

    for(auto& p: packets) {
        ROBuf frame;
        PACKET_OPCODE opcode;
        uint8_t id;
        std::tie(frame, opcode, id) = p;

        if(this->m_map.find(id) == this->m_map.end()) {
            if(opcode ==  PACKET_OP_ACCEPT_CONNECTION)
                continue;
            this->close();
            return;
        }

        ClientProxyAbstraction* cc = this->m_map[id];

        switch (opcode) {
            case PACKET_OP_WRITE:
                cc->pushData(frame);
                break;
            case PACKET_OP_END_CONNECTION:
                cc->serverEnd();
                break;
            case PACKET_OP_CLOSE_CONNECTION:
                cc->close();
                break;
            case PACKET_OP_ACCEPT_CONNECTION:
                if(this->m_wait_new_connection.find(id) == this->m_wait_new_connection.end()) {
                    __logger->warn("ConnectionProxy recieves a packet to ClientConnection which doesn't exists. Accept_Connection");
                    this->send_close_connection(id);
                    cc->close();
                } else {
                    this->m_wait_new_connection.erase(this->m_wait_new_connection.find(id));
                    this->m_map[id]->connectSuccess();
                }
                break;
            case PACKET_OP_REJECT_CONNECTION:
                if(this->m_wait_new_connection.find(id) == this->m_wait_new_connection.end()) {
                    __logger->warn("ConnectionProxy recieves a packet to ClientConnection which doesn't exists. REJECT");
                    cc->close();
                } else {
                    this->m_wait_new_connection.erase(this->m_wait_new_connection.find(id));
                    this->m_map[id]->connectFail(ConnectResult::SERVER_FAILURE);
                }
                break;
            case PACKET_OP_CREATE_CONNECTION:
            case PACKET_OP_RESERVED:
            default:
                __logger->warn("KProxyClient recieve a packet with unexpected opcode. close current connection it");
                this->close();
                return;
        }
    }
} //}

using __send_close_connection_state = ConnectionProxy_callback_state;
static void __send_close_connection_callback(ROBuf buf, int status, void* data) //{
{
    __send_close_connection_state* msg =
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0)
        _this->close();
} //}
/**
 * send a packet that indicate close connection id of which is #id
 * @param {uint8_t id} the id should be deallocated by @ConnecitonProxy::remove_connection() */
void ConnectionProxy::send_close_connection(uint8_t id) //{
{
    __logger->debug("call %s", FUNCNAME);
    auto pkt = encode_packet(PACKET_OP_CLOSE_CONNECTION, id, ROBuf((char*)"close", 5));

    auto ptr = new __send_close_connection_state(this);
    this->add_callback(ptr);

    this->_write(pkt, __send_close_connection_callback, ptr);
} //}

void ConnectionProxy::connectToServer(ConnectCallback cb, void* data) {this->__connectToServer(cb, data);}

struct __new_connection_write_state: public CallbackPointer {
    ConnectionProxy*        _this;
    uint8_t                 _id;
    __new_connection_write_state(decltype(_this) _this, uint8_t id):
        _this(_this), _id(id) {}
};
using __new_connection_timeout_state = __new_connection_write_state;
/** send a packet which inform remote server to create a new connection to #addr:#port */
void ConnectionProxy::new_connection(uint8_t id, ClientProxyAbstraction* obj,const std::string& addr, uint16_t port, int timeout_ms) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_map.find(id) != this->m_map.end());
    assert(this->connected());

    ROBuf buf = ROBuf(addr.size() + 2);
    memcpy(buf.__base(), addr.c_str(), addr.size());
    *(uint16_t*)(&buf.__base()[addr.size()]) = k_htons(port);
    auto send_buf = encode_packet(PACKET_OP_CREATE_CONNECTION, id, buf);

    this->m_wait_new_connection.insert(id);

    auto write_ptr = new __new_connection_write_state(this, id);
    this->add_callback(write_ptr);

    this->_write(send_buf, ConnectionProxy::new_connection_write_callback, write_ptr);

    auto timeout_ptr = new __new_connection_timeout_state(this, id);
    this->add_callback(timeout_ptr);

    this->timeout(new_connection_timer_callback, timeout_ptr, timeout_ms);
} //}
/** [static] callback for @EBStreamAbstraction::_write() in @ConnectionProxy::new_connection() */
void ConnectionProxy::new_connection_write_callback(ROBuf buf, int status, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    __new_connection_write_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto id = msg->_id;
    auto run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0) {
        if(_this->m_wait_new_connection.find(id) == _this->m_wait_new_connection.end())
            return;

        assert(_this->m_map.find(id) != _this->m_map.end());
        _this->m_wait_new_connection.erase(_this->m_wait_new_connection.find(id));
        _this->m_map[id]->connectFail(ConnectResult::SERVER_FAILURE);
        return;
    }
} //}
/** [static] callback for @EBStreamAbstraction::timeout() in @ConnectionProxy::new_connection() */
void ConnectionProxy::new_connection_timer_callback(void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    __new_connection_write_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto id = msg->_id;
    auto run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(_this->m_wait_new_connection.find(id) == _this->m_wait_new_connection.end())
        return;

    assert(_this->m_map.find(id) != _this->m_map.end());
    _this->m_wait_new_connection.erase(_this->m_wait_new_connection.find(id));
    _this->m_map[id]->connectFail(ConnectResult::SERVER_FAILURE);
    return;
} //}

/**
 * deallocate the memory that allocated to this ClientConnection object
 * @param {uint8_t id} the id of the ClientConnection object
 * @param {ClientConnection* obj} the pointer points to the ClientConnection object */
void ConnectionProxy::remove_clientConnection(uint8_t id, ClientProxyAbstraction* obj) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_map.find(id) != this->m_map.end());
    assert(this->m_map[id] == obj);
    this->m_map.erase(this->m_map.find(id));
    if(this->m_wait_new_connection.find(id) != this->m_wait_new_connection.end()) {
        this->m_wait_new_connection.erase(this->m_wait_new_connection.find(id));
    }
    delete obj;
} //}

/** function for flow control */
using __startread_stopread_state = ConnectionProxy_callback_state;
static void __startstop_read_write_callback(ROBuf buf, int status, void* data) //{
{
    __startread_stopread_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    assert(msg);

    auto _this = msg->_this;
    auto run   = msg->CanRun();

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0)
        _this->close();
} //}
void ConnectionProxy::sendStartConnectionRead(uint8_t id) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(id < SINGLE_TSL_MAX_CONNECTION);
    ROBuf buf = encode_packet_header(PACKET_OPCODE::PACKET_OP_START_READ, id, 0);

    auto ptr = new __startread_stopread_state(this);
    this->add_callback(ptr);

    this->_write(buf, __startstop_read_write_callback, ptr);
} //}
void ConnectionProxy::sendStopConnectionRead(uint8_t id) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(id < SINGLE_TSL_MAX_CONNECTION);
    ROBuf buf = encode_packet_header(PACKET_OPCODE::PACKET_OP_STOP_READ, id, 0);

    auto ptr = new __startread_stopread_state(this);
    this->add_callback(ptr);

    this->_write(buf, __startstop_read_write_callback, ptr);
} //}
using __send_end_connection_state = ConnectionProxy_callback_state;
#define __send_end_connection_callback __send_close_connection_callback
void ConnectionProxy::connectionEnd(uint8_t id, ClientProxyAbstraction* obj) //{
{
    __logger->debug("call %s", FUNCNAME);
    auto pkt = encode_packet(PACKET_OP_END_CONNECTION, id, ROBuf((char*)"end", 3));

    auto ptr = new __send_end_connection_state(this);
    this->add_callback(ptr);

    this->_write(pkt, __send_end_connection_callback, ptr);
} //}

/** wrapper of @ConnectionProxy::_write() */
void ConnectionProxy::write(uint8_t id, ClientProxyAbstraction* obj, ROBuf buf, WriteCallbackMM cb, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(id < SINGLE_TSL_MAX_CONNECTION);
    ROBuf x = encode_packet_header(PACKET_OPCODE::PACKET_OP_WRITE, id, buf.size()) + buf;
    return this->_write(x, cb, data);
} //} 

uint8_t ConnectionProxy::getConnectionNumbers() //{
{
    assert(this->m_map.size() <= 0xff);
    return this->m_map.size();
} //}
bool ConnectionProxy::connected() {return this->m_state == __State::STATE_BUILD;}
bool ConnectionProxy::full()      {return this->getConnectionNumbers() == SINGLE_TSL_MAX_CONNECTION;}
bool ConnectionProxy::uninit()    {return this->m_state == __State::STATE_INITIAL;}
/** allocate an id to #connection 
 * @precondition this object must own avaliable id, otherwise abort */
uint8_t ConnectionProxy::requireAnId(ClientProxyAbstraction* connection) //{
{
    __logger->debug("call %s", FUNCNAME);
    uint8_t id = this->get_id();
    assert(id < SINGLE_TSL_MAX_CONNECTION);
    assert(this->m_map.find(id) == this->m_map.end());
    this->m_map[id] = connection;
    return id;
} //}

/** close this object */
void ConnectionProxy::close() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_state != __State::STATE_CLOSED);
    this->m_state = __State::STATE_CLOSED;

    auto mm = this->m_map;
    for(auto& x: mm)
        x.second->close();

    this->mp_server->remove_proxy(this);
} //}

ConnectionProxy::~ConnectionProxy() //{
{
    __logger->debug("call %s", FUNCNAME);
    if(this->m_connect_cb != nullptr) {
        this->m_connect_cb(-1, this->m_connect_cb_data);
        this->m_connect_cb = nullptr;
        this->m_connect_cb_data = nullptr;
    }
} //}


NS_PROXY_CLIENT_END

