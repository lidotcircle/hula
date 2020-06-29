#include "../include/kserver_server2net.h"
#include "../include/ObjectFactory.hpp"
#include "../include/config.h"
#include "../include/ObjectFactory.hpp"
#include "../include/callback_data.h"


NS_PROXY_SERVER_START

ServerToNetConnection::ServerToNetConnection(ClientConnectionProxy* proxy, ConnectionId id, 
                                             const std::string& addr, uint16_t port) //{
{
    __logger->debug("call %s: [%s:%d]", FUNCNAME, addr.c_str(), port);

    this->mp_proxy = proxy;
    this->m_id = id;

    this->m_addr = addr;
    this->m_port = port;

    this->m_net_to_user_buffer = 0;
    this->m_user_to_net_buffer = 0;

    this->m_net_tcp_start_read = false;

    this->__connect();
} //}

/** connect to server throught internet */
void ServerToNetConnection::__connect() //{
{
    __logger->debug("call %s", FUNCNAME);
    uint32_t ipv4_addr; // TODO support IPV6
    if(str_to_ip4(this->m_addr.c_str(), &ipv4_addr)) {
        struct addrinfo info;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = k_ntohs(this->m_port); // FIXME
        addr.sin_addr.s_addr = k_ntohl(ipv4_addr);
        info.ai_family = AF_INET;
        info.ai_addrlen = sizeof(sockaddr_in); // FIXME ??
        info.ai_canonname = nullptr;
        info.ai_next = nullptr;
        info.ai_flags = 0;
        info.ai_addr = (sockaddr*)&addr;

        auto ptr = new CBD::ServerToNetConnection$__connect$getaddrinfo(this, false, this->m_port);
        this->add_callback(ptr);

        ServerToNetConnection::tcp2net_getaddrinfo_callback(this, &info, 0, ptr);
    } else {
        auto ptr = new CBD::ServerToNetConnection$__connect$getaddrinfo(this, true, this->m_port);
        this->add_callback(ptr);

        this->getaddrinfo(this->m_addr.c_str(), ServerToNetConnection::tcp2net_getaddrinfo_callback, ptr);
    }
} //}
/** [static] callback for uv_getaddrinfo() in @__connect() */
void ServerToNetConnection::tcp2net_getaddrinfo_callback(EventEmitter* obj, struct addrinfo* res, int status, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    struct addrinfo *a;
    struct sockaddr_in* m;

    CBD::ServerToNetConnection$__connect$getaddrinfo* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CBD::SBase*>(data));
    assert(msg);
    auto _this = msg->_this;
    auto clean = msg->_clean;
    auto run   = msg->CanRun();
    auto port  = msg->_port;
    delete msg;

    if(!run) {
        if(clean) _this->freeaddrinfo(res);
        return;
    }
    _this->remove_callback(msg);

    if(status < 0) {
        __logger->warn("%s: get dns fail with %d", FUNCNAME, status);
        _this->mp_proxy->reject_connection(_this->m_id, NEW_CONNECTION_REPLY::GET_DNS_FAIL);
        if(clean) _this->freeaddrinfo(res);
        return;
    }

    for(a = res; a != nullptr; a = a->ai_next) {
        if(sizeof(struct sockaddr_in) != a->ai_addrlen) { // IPV6 TODO
            logger->info("%s: query dns get an address that isn't ipv4 address", FUNCNAME);
            continue;
        } else break;
    }
    if(a == nullptr) {
        __logger->warn("%s: query dns fail because of without a valid ipv4 address", FUNCNAME);
        if(clean) _this->freeaddrinfo(res);
        _this->mp_proxy->reject_connection(_this->m_id, NEW_CONNECTION_REPLY::GET_DNS_FAIL);
        return;
    }
    m = (struct sockaddr_in*)a->ai_addr;
    __logger->info("%s: %s", FUNCNAME, ip4_to_str(m->sin_addr.s_addr));
    m->sin_port = k_htons(port);
    _this->__connect_with_sockaddr((sockaddr*)m);
    if(clean) _this->freeaddrinfo(res);
} //}

/** connect to server with #addr */
void ServerToNetConnection::__connect_with_sockaddr(sockaddr* addr) //{
{
    __logger->debug("call %s: [address=%s, port=%d]", FUNCNAME, 
            ip4_to_str(((sockaddr_in*)addr)->sin_addr.s_addr), 
            k_ntohs(((sockaddr_in*)addr)->sin_port));

    auto ptr = new CBD::ServerToNetConnection$__connect_with_sockaddr$connect();
    this->add_callback(ptr);
    this->connect(addr, ServerToNetConnection::tcp2net_connect_callback, ptr);
} //}
/** [static] callback for uv_tcp_connect() in @__connect_with_sockaddr() */
void ServerToNetConnection::tcp2net_connect_callback(EventEmitter* obj, int status, void* data) //{ static
{
    __logger->debug("call %s", FUNCNAME);
    CBD::ServerToNetConnection$__connect_with_sockaddr$connect* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CBD::SBase*>(data));

    bool run = msg->CanRun();
    delete msg;
    if(!run) return;

    ServerToNetConnection* _this = dynamic_cast<ServerToNetConnection*>(obj);
    assert(_this);
    _this->remove_callback(msg);

    if(status < 0) {
        _this->mp_proxy->reject_connection(_this->m_id, NEW_CONNECTION_REPLY::CONNECT_FAIL);
        return;
    }
    _this->mp_proxy->accept_connection(_this->m_id);
    _this->__start_net_to_user();
} //}

/** start relay from net to user */
void ServerToNetConnection::__start_net_to_user() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_net_tcp_start_read == false);
    this->m_net_tcp_start_read = true;
    this->start_read();
} //}

/** write data to user by pack as a packet */
void ServerToNetConnection::_write_to_user(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    this->m_net_to_user_buffer += buf.size();
    auto ptr = new CBD::ServerToNetConnection$write_to_user$write(this);
    this->add_callback(ptr);
    this->mp_proxy->write(this->m_id, buf, ServerToNetConnection::write_to_user_callback, ptr);

    if(this->m_net_to_user_buffer > PROXY_MAX_BUFFER_SIZE) {
        this->stop_read();
        this->m_net_tcp_start_read = false;
    }
} //}
/** [static] callback for ClientConnecitonProxy::write() in @_write_to_user() */
void ServerToNetConnection::write_to_user_callback(ROBuf buf, void* data, int status, bool run) //{
{
    __logger->debug("call %s", FUNCNAME);

    CBD::ServerToNetConnection$write_to_user$write* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CBD::SBase*>(data));
    assert(msg);
    auto _this = msg->_this;
    run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    _this->m_net_to_user_buffer -= buf.size();

    if(status < 0) {
        _this->close();
        return;
    }

    if(_this->m_net_to_user_buffer < PROXY_MAX_BUFFER_SIZE && _this->m_net_tcp_start_read == false)
        _this->__start_net_to_user();
} //}

/** implement abstract method */
void ServerToNetConnection::read_callback(ROBuf buf, int status) //{
{
    if(status < 0)
        this->close();
    else
        this->_write_to_user(buf);
} //}

/** push data from user to net */
void ServerToNetConnection::PushData(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    this->m_user_to_net_buffer += buf.size();
    auto ptr = new CBD::ServerToNetConnection$PushData$write();
    this->add_callback(ptr);

    this->_write(buf, ServerToNetConnection::tcp2net_write_callback, ptr);

    if(this->m_user_to_net_buffer > PROXY_MAX_BUFFER_SIZE) {
        // TODO send a packet to inform client stop read the socket
        this->m_inform_client_stop_read = true;
        return;
    }
} //}
/** [static] callback for _write() in @PushData() */
void ServerToNetConnection::tcp2net_write_callback(EventEmitter* obj, ROBuf buf, int status, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    CBD::ServerToNetConnection$PushData$write* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CBD::SBase*>(data));
    assert(msg);
    ServerToNetConnection* _this = dynamic_cast<decltype(_this)>(obj);
    bool run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    _this->m_user_to_net_buffer -=  buf.size();
    if(status < 0) {
        _this->close();
        return;
    }

    if(_this->m_user_to_net_buffer < PROXY_MAX_BUFFER_SIZE && _this->m_inform_client_stop_read) {
        // TODO send back a packet inform client continue to read the socket
        _this->m_inform_client_stop_read = false;
    }
} //}

/** close this object */
void ServerToNetConnection::close() //{
{
    __logger->debug("call %s", FUNCNAME);
    this->mp_proxy->remove_connection(this->m_id, this);
} //}

ServerToNetConnection::~ServerToNetConnection() {}

NS_PROXY_SERVER_END
