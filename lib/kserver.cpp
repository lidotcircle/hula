#include "../include/kserver.h"
#include "../include/logger.h"
#include "../include/utils.h"
#include "../include/kpacket.h"
#include "../include/robuf.h"
#include "../include/uv_callback_data.h"
#include "../include/libuv_utils.h"

#include <uv.h>

#include <stdlib.h>
#include <assert.h>

#include <tuple>

#define CONNECTION_MAX_BUFFER_SIZE (2 * 1024 * 1024) // 2M

template<typename T>
static void delete_closed_handle(uv_handle_t* h) {
    delete static_cast<T>(static_cast<void*>(h));
}

namespace KProxyServer {

/**                     class Server                  *///{

Server::Server(uv_loop_t* loop, const std::string& config_file): //{
    bind_addr(0),
    bind_port(1080),
    mp_uv_loop(loop),
    m_tsl_list()
{
    __logger->debug("call %s", FUNCNAME);
    this->mp_uv_tcp = new uv_tcp_t();
    uv_tcp_init(this->mp_uv_loop, this->mp_uv_tcp);

    this->mp_config = new ServerConfig(this->mp_uv_loop, config_file);

    uv_handle_set_data((uv_handle_t*)this->mp_uv_tcp, this);
} //}

void Server::on_config_load(int error, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    Server* _this = (Server*) data;
    if(error > 0) {
        logger->error("load config file fail");
        exit(1);
    }
    _this->bind_addr = _this->mp_config->BindAddr();
    _this->bind_port = _this->mp_config->BindPort();
    _this->__listen();
} //}
int Server::__listen() //{ 
{
    __logger->debug("call %s", FUNCNAME);
    sockaddr_in addr;

    uint32_t network_order_addr = k_htonl(this->bind_addr);

    uv_ip4_addr(ip4_to_str(network_order_addr), this->bind_port, &addr);
    int s = uv_tcp_bind(this->mp_uv_tcp, (sockaddr*)&addr, 0);
    if(s != 0) {
        logger->error("bind error %s:%d", ip4_to_str(network_order_addr), this->bind_port);
        return s;
    }
    s = uv_listen((uv_stream_t*)this->mp_uv_tcp, DEFAULT_BACKLOG, Server::on_connection);
    if(s != 0) {
        logger->error("listen error %s:%d", ip4_to_str(network_order_addr), this->bind_port);
        return s;
    }
    logger->debug("listen at %s:%d", ip4_to_str(network_order_addr), this->bind_port);
    return 0;
} //}

void Server::remove_proxy(ClientConnectionProxy* p) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_tsl_list.find(p) != this->m_tsl_list.end());
    this->m_tsl_list.erase(this->m_tsl_list.find(p));
    delete p;
} //}

int Server::listen() //{ 
{
    __logger->debug("call %s", FUNCNAME);
    this->mp_config->loadFromFile(Server::on_config_load, this);
    return 0;
} //}

void Server::close() //{
{
    __logger->debug("call %s", FUNCNAME);
    auto tsl_list_copy = this->m_tsl_list;
    for(auto&x: tsl_list_copy)
        x->close();

    delete this->mp_config;
    this->mp_config = nullptr;
    uv_close((uv_handle_t*)this->mp_uv_tcp, delete_closed_handle<decltype(this->mp_uv_tcp)>);
    this->mp_uv_tcp = nullptr;

    return;
} //}

Server::~Server() //{
{
} //}

/** connection callback function */
void Server::on_connection(uv_stream_t* stream, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    if(status < 0) {
        __logger->warn("new connection error");
        return;
    }

    Server* _this = (Server*)uv_handle_get_data((uv_handle_t*)stream);
    uv_tcp_t* client = new uv_tcp_t();
    uv_tcp_init(_this->mp_uv_loop, client);

    if(uv_accept(stream, (uv_stream_t*)client) < 0) {
        __logger->warn("accept new connection error");
        delete client;
        return;
    }

    connectionArgv cb_arg = connectionArgv(_this, client);
    _this->emit("connection", &cb_arg);

    _this->dispatch_new_connection(client);
    return;
} //}

/** dispatch connection to wrapper object */
void Server::dispatch_new_connection(uv_tcp_t* connection) //{
{
    __logger->debug("call %s", FUNCNAME);
    ClientConnectionProxy* newProxy = new ClientConnectionProxy(this, connection);
    this->m_tsl_list.insert(newProxy);
} //}
//}

/**                     class ClientConnectionProxy                  *///{

/** constructor */
ClientConnectionProxy::ClientConnectionProxy(Server* server, uv_tcp_t* connection): m_remains() //{
{
    __logger->debug("call %s", FUNCNAME);
    this->mp_server = server;
    this->mp_connection = connection;
    this->mp_loop = uv_handle_get_loop((uv_handle_t*)this->mp_connection);

    uv_handle_set_data((uv_handle_t*)this->mp_connection, this);

    this->m_connection_read = false;
    this->m_state = __State::INIT;

    this->server_tsl_handshake();
} //}

void ClientConnectionProxy::malloc_cb(uv_handle_t* h, size_t suggested_size, uv_buf_t* out) //{
{
    __logger->debug("call %s", FUNCNAME);
    out->base = (char*)malloc(suggested_size);
    out->len  = suggested_size;
    return;
} //}
void ClientConnectionProxy::user_read_cb  (uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    ClientConnectionProxy* _this = 
        static_cast<decltype(_this)>(uv_handle_get_data((uv_handle_t*)stream));
    assert(_this != nullptr);
    if(nread <= 0) {
        free(buf->base);
        _this->close();
        return;
    }
    ROBuf xbuf(buf->base, nread, 0, free);
    _this->dispatch_new_encrypted_data(xbuf);
} //}
void ClientConnectionProxy::user_stream_write_cb(uv_write_t* req,  int status) //{ TODO
{
    __logger->debug("call %s", FUNCNAME);
    UVC::ClientConnectionProxy$_write$uv_write* msg = 
        dynamic_cast<decltype(msg)>(static_cast<UVC::UVCBaseServer*>(uv_req_get_data((uv_req_t*)req)));
    msg->_this->callback_remove(msg);
    auto cb = msg->_cb;
    auto data = msg->_data;
    auto _this = msg->_this;
    auto uv_buf = msg->_uv_buf;
    auto robuf = msg->_mem_holder;
    bool should_run = msg->should_run;
    delete msg;
    delete uv_buf;
    delete req;

    if(cb != nullptr) {
        cb(should_run, status, robuf, data);
    } else {
        delete robuf;
    }

    if(!should_run) {
        return;
    }

    if(status < 0) {
        _this->close();
    }
    return;
} //}

void ClientConnectionProxy::dispatch_new_encrypted_data(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    // pass
    if(this->m_state > __State::TSL_HAND_SHAKE)
        this->dispatch_new_unencrypted_data(buf);
    else
        assert(false && "unimplemented tsl");
} //}
void ClientConnectionProxy::dispatch_new_unencrypted_data(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_state > __State::TSL_HAND_SHAKE);
    switch(this->m_state) {
        case __State::USER_AUTHENTICATION:
            this->dispatch_authentication_data(buf);
            break;
        case __State::BUILD:
            this->dispatch_packet_data(buf);
            break;
        case __State::INIT:
        case __State::TSL_HAND_SHAKE:
        case __State::ERROR:
        case __State::CLOSING:
        case __State::CLOSED:
        defualt:
            assert(false && "something wrong");
    }
} //}
void ClientConnectionProxy::dispatch_authentication_data(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_state == __State::USER_AUTHENTICATION);
    this->m_remains = this->m_remains + buf;
    if(this->m_remains.size() < 2) return;
    uint8_t username_len = this->m_remains.base()[0];
    if(this->m_remains.size() < username_len + 3) return;
    uint8_t password_len = this->m_remains.base()[username_len + 1];
    if(this->m_remains.size() < username_len + password_len + 2) return;

    char* username = (char*)malloc(username_len + 1);
    char* password = (char*)malloc(password_len + 1);
    memcpy(username, this->m_remains.base() + 1, username_len);
    memcpy(password, this->m_remains.base() + 2 + username_len, password_len);
    username[username_len] = '\0';
    password[password_len] = '\0';
    __logger->info("Authentication: [username: %s, password: %s]", username, password);

    bool authenticate_pass = this->mp_server->mp_config->validateUser(username, password);

    free(username);
    free(password);

    if(authenticate_pass) {
        __logger->info("Authentication success");
        this->m_remains = this->m_remains + (username_len + password_len + 2);
        this->m_state = __State::BUILD;
        this->_write(ROBuf((char*)"\xff\x00", 2), nullptr, nullptr);
    } else {
        __logger->warn("Authentication fail");
        this->_write(ROBuf((char*)"\x00\x00", 2), nullptr, nullptr);
        this->close();
    }
} //}
void ClientConnectionProxy::dispatch_packet_data(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    auto result = decode_all_packet(this->m_remains, buf);
    bool noerror;
    std::vector<std::tuple<ROBuf, PACKET_OPCODE, uint8_t>> x;
    std::tie(noerror, x, this->m_remains) = result;

    if(!noerror) {
        // packet error, give up TODO
        this->close();
        return;
    }

    for(auto& z: x) {
        ROBuf a;
        PACKET_OPCODE b;
        uint8_t id;
        std::tie(a, b, id) = z;

        switch(b) {
            case PACKET_OP_NEW:
                this->dispatch_new(id, a);
                break;
            case PACKET_OP_REG:
                if(this->m_map.find(id) != this->m_map.end()) {
                    this->dispatch_reg(id, a);
                } else {
                    this->close();
                    __logger->warn("ClientConnectionProxy: unexpected id REG");
                }
                break;
            case PACKET_OP_CLOSE:
                if(this->m_map.find(id) != this->m_map.end())
                    this->dispatch_close(id, a);
                else
                    __logger->warn("ClientConnectionProxy: unexpected id CLOSE");
                break;
            case PACKET_OP_RESERVED:
            default:
                logger->warn("unexcepted packet which use reserved opcode");
                this->close();
                break;
        }
    }
} //}

/*
 * the request has format like |    address:port   | 
 *                             |      buf.size()   |*/
void ClientConnectionProxy::dispatch_new(uint8_t id, ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(id < 1 << 6);
    if(this->m_map.find(id) != this->m_map.end()) {
        logger->warn("ClientConnectionProxy::dispatch_new(): bad connection id");
        std::cout << (int)id << std::endl;
        for(auto& x: this->m_map)
            std::cout << (int)x.first << " ";
        std::cout << std::endl;
        this->close();
        return;
    }

    if(buf.size() < 4) {
        logger->warn("ClientConnectionProxy::dispatch_new(): bad new connection request");
        this->close();
        return;
    }

    uint16_t port;
    memcpy(&port, buf.base() + buf.size() - 2, 2);
    port = k_ntohs(port);

    char* addr = (char*)malloc(buf.size() - 2 + 1);
    memcpy(addr, buf.base(), buf.size() - 2);
    addr[buf.size() - 2] = '\0';

    this->m_wait_connect.insert(id);
    auto newcon = new ServerToNetConnection(this, this->mp_loop, id, std::string(addr), port);
    this->m_map[id] = newcon;

    free(addr);

    return;
} //}
void ClientConnectionProxy::dispatch_reg(uint8_t id, ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_map.find(id) != this->m_map.end());
    this->m_map[id]->PushData(buf);
} //}
void ClientConnectionProxy::dispatch_close(uint8_t id, ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_map.find(id) != this->m_map.end());
    ServerToNetConnection* s = this->m_map[id];
    if( buf.size() > 0) {
        char* reason = (char*)malloc(buf.size() + 1);
        memcpy(reason, buf.base(), buf.size());
        reason[buf.size()] = '\0';
        logger->info("ClientConnectionProxy: close connection because %s", reason);
        free(reason);
    }
    s->close();
} //}

void ClientConnectionProxy::server_tsl_handshake() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_state == __State::INIT);
    this->m_state = __State::TSL_HAND_SHAKE;
    assert(this->m_connection_read == false);
    uv_read_start((uv_stream_t*)this->mp_connection, 
            ClientConnectionProxy::malloc_cb, 
            ClientConnectionProxy::user_read_cb);
    this->m_connection_read = true;
    this->user_authenticate(); // TODO
} //}
void ClientConnectionProxy::user_authenticate() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_state == __State::TSL_HAND_SHAKE);
    this->m_state = __State::USER_AUTHENTICATION;
    return;
} //}
void ClientConnectionProxy::start_relay() //{
{
    __logger->debug("call %s", FUNCNAME);
    return;
} //}

int ClientConnectionProxy::_write(ROBuf buf, WriteCallback cb, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->mp_connection != nullptr);

    uv_buf_t* uv_buf = new uv_buf_t();
    uv_buf->base = buf.__base();
    uv_buf->len = buf.size();

    ROBuf* mem_holder = new ROBuf(buf);

    uv_write_t* req = new uv_write_t();
    auto ptr = new UVC::ClientConnectionProxy$_write$uv_write(this, cb, data, mem_holder, uv_buf);
    uv_req_set_data((uv_req_t*)req, ptr);
    this->callback_insert(ptr, this);

    this->m_net_to_user_buffer += buf.size();
    return uv_write(req, (uv_stream_t*)this->mp_connection, uv_buf, 1, ClientConnectionProxy::user_stream_write_cb);
} //}

int ClientConnectionProxy::close_connection(uint8_t id) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(id < SINGLE_TSL_MAX_CONNECTION);
    assert(this->m_map.find(id) != this->m_map.end());
    char reason[] = "close";
    auto b = encode_packet(PACKET_OPCODE::PACKET_OP_CLOSE, id, ROBuf(reason, strlen(reason)));
    int ret = this->_write(b, nullptr, nullptr);
    this->m_map.erase(this->m_map.find(id));
    return ret;
} //}
int ClientConnectionProxy::accept_connection(uint8_t id) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(id < SINGLE_TSL_MAX_CONNECTION);
    assert(this->m_map.find(id) != this->m_map.end());
    char reason = NEW_CONNECTION_REPLY::SUCCESS;
    auto b = encode_packet(PACKET_OPCODE::PACKET_OP_CONNECT, id, ROBuf(&reason, 1));
    return this->_write(b, nullptr, nullptr);
} //}
int ClientConnectionProxy::reject_connection(uint8_t id, NEW_CONNECTION_REPLY reason) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(id < SINGLE_TSL_MAX_CONNECTION);
    assert(this->m_map.find(id) != this->m_map.end());
    auto b = encode_packet(PACKET_OPCODE::PACKET_OP_REJECT, id, ROBuf(&reason, 1));
    return this->_write(b, nullptr, nullptr);
} //}

void ClientConnectionProxy::remove_connection(uint8_t id, ServerToNetConnection* con) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_map.find(id) != this->m_map.end());
    assert(this->m_map[id] == con);
    this->m_map.erase(this->m_map.find(id));
    delete con;

    for(auto& x: this->m_callbacks) {
        if(x.second == con)
            x.second = nullptr;
    }
} //}

static void __close(void* data) {static_cast<ClientConnectionProxy*>(data)->close();}
static int close_ticks = 0;
#define PER_INFO_BY_CLOSE_TICK 1000
void ClientConnectionProxy::close() //{
{
    if((close_ticks++ % PER_INFO_BY_CLOSE_TICK) == 0)
        __logger->debug("call %s", FUNCNAME);

    auto m = this->m_map;
    for(auto& x: m)
        x.second->close();

    for(auto& x: this->m_callbacks)
        x.first->should_run =false;

    if(this->mp_connection) {
        if(this->m_connection_read)
            uv_read_stop((uv_stream_t*)this->mp_connection);
        this->m_connection_read = false;
        uv_close((uv_handle_t*)this->mp_connection, delete_closed_handle<decltype(this->mp_connection)>);
        this->mp_connection = nullptr;
    }

    if(this->m_callbacks.size() != 0)
        UVU::setTimeout(this->mp_loop, 500, __close, this);
    else
        this->mp_server->remove_proxy(this);
    return;
} //}

int ClientConnectionProxy::write(uint8_t id, ROBuf buf, WriteCallback cb, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    auto m = encode_packet(PACKET_OPCODE::PACKET_OP_REG, id, buf);
    return this->_write(m, cb, data);
} //}

void ClientConnectionProxy::callback_insert(UVC::UVCBaseServer* ptr, void* obj) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_callbacks.find(ptr) == this->m_callbacks.end());
    this->m_callbacks[ptr] = obj;
} //}
void* ClientConnectionProxy::callback_remove(UVC::UVCBaseServer* ptr) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_callbacks.find(ptr) != this->m_callbacks.end());
    auto ret = this->m_callbacks[ptr];
    this->m_callbacks.erase(this->m_callbacks.find(ptr));
    return ret;
} //}

//}

/**                     class ServerToNetConnection            */ //{
ServerToNetConnection::ServerToNetConnection(ClientConnectionProxy* p, uv_loop_t* loop, ConnectionId id, 
                              const std::string& addr, uint16_t port) //{
{
    __logger->debug("call %s: [%s:%d]", FUNCNAME, addr.c_str(), port);
    this->mp_proxy = p;
    this->m_id = id;

    this->mp_loop = loop;
    this->mp_tcp = new uv_tcp_t();
    uv_tcp_init(this->mp_loop, this->mp_tcp);
    uv_handle_set_data((uv_handle_t*)this->mp_tcp, this);
    this->m_net_tcp_start_read = false;

    this->m_addr = addr;
    this->m_port = port;

    this->m_net_to_user_buffer = 0;
    this->m_user_to_net_buffer = 0;

    this->__connect();
} //}

void ServerToNetConnection::__connect() //{
{
    __logger->debug("call %s", FUNCNAME);
    uint32_t ipv4_addr; // TODO maybe support IPV6
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

        uv_getaddrinfo_t req;
        auto ptr = new UVC::ServerToNetConnection$__connect$uv_getaddrinfo(this->mp_proxy, this, this->m_port, false);
        uv_req_set_data((uv_req_t*)&req, ptr);
        this->mp_proxy->callback_insert(ptr, this);

        ServerToNetConnection::tcp2net_getaddrinfo_callback(&req, 0, &info);
    } else {
        struct addrinfo hints;
        hints.ai_family = AF_INET;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = 0;

        uv_getaddrinfo_t* p_req = new uv_getaddrinfo_t();
        auto ptr = new UVC::ServerToNetConnection$__connect$uv_getaddrinfo(this->mp_proxy, this, this->m_port, true);
        uv_req_set_data((uv_req_t*)p_req, ptr);
        this->mp_proxy->callback_insert(ptr, this);

        uv_getaddrinfo(this->mp_loop, p_req, 
                ServerToNetConnection::tcp2net_getaddrinfo_callback,
                this->m_addr.c_str(), "80", &hints);
    }
} //}
void ServerToNetConnection::tcp2net_getaddrinfo_callback(uv_getaddrinfo_t* req, int status, struct addrinfo* res) //{
{
    __logger->debug("call %s", FUNCNAME);
    struct addrinfo *a;
    struct sockaddr_in* m;

    UVC::ServerToNetConnection$__connect$uv_getaddrinfo* msg = 
        dynamic_cast<decltype(msg)>(static_cast<UVC::UVCBaseServer*>(uv_req_get_data((uv_req_t*)req)));
    assert(msg);

    ClientConnectionProxy* _proxy = msg->_proxy;
    ServerToNetConnection* _this = msg->_this;
    uint16_t port = msg->_port;
    bool clean = msg->_clean;
    bool should_run = msg->should_run;
    delete msg;
    if(clean) delete req;
    auto pp = _proxy->callback_remove(msg);
    if(pp == nullptr) should_run = false;

    if(!should_run) {
        if(clean) uv_freeaddrinfo(res);
        return;
    }

    assert(pp == _this);

    if(status < 0) {
        __logger->warn("%s: get dns fail with %d", FUNCNAME, status);
        _this->mp_proxy->reject_connection(_this->m_id, NEW_CONNECTION_REPLY::GET_DNS_FAIL);
        if(clean) uv_freeaddrinfo(res);
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
        if(clean) uv_freeaddrinfo(res);
        _this->mp_proxy->reject_connection(_this->m_id, NEW_CONNECTION_REPLY::GET_DNS_FAIL);
        return;
    }
    m = (struct sockaddr_in*)a->ai_addr;
    __logger->info("%s: %s", FUNCNAME, ip4_to_str(m->sin_addr.s_addr));
    m->sin_port = k_htons(port);
    _this->__connect_with_sockaddr((sockaddr*)m);
    if(clean) uv_freeaddrinfo(res);
} //}

void ServerToNetConnection::__connect_with_sockaddr(sockaddr* addr) //{
{
    __logger->debug("call %s: [address=%s, port=%d]", FUNCNAME, 
            ip4_to_str(((sockaddr_in*)addr)->sin_addr.s_addr), 
            k_ntohs(((sockaddr_in*)addr)->sin_port));
    assert(this->mp_tcp != nullptr);

    uv_connect_t* req = new uv_connect_t();
    auto ptr = new UVC::ServerToNetConnection$__connect_with_sockaddr$uv_tcp_connect(this->mp_proxy, this);
    this->mp_proxy->callback_insert(ptr, this);
    uv_req_set_data((uv_req_t*) req, ptr);

    uv_tcp_connect(req, this->mp_tcp, addr, ServerToNetConnection::tcp2net_connect_callback);
} //}
void ServerToNetConnection::tcp2net_connect_callback(uv_connect_t* req, int status) //{ static
{
    __logger->debug("call %s", FUNCNAME);
    UVC::ServerToNetConnection$__connect_with_sockaddr$uv_tcp_connect* msg = 
        dynamic_cast<decltype(msg)>(static_cast<UVC::UVCBaseServer*>(uv_req_get_data((uv_req_t*)req)));

    ServerToNetConnection* _this = msg->_this;
    ClientConnectionProxy* _proxy = msg->_proxy;
    bool should_run = msg->should_run;
    auto pp =_proxy->callback_remove(msg);
    if(pp == nullptr) should_run = false;
    delete msg;
    delete req;

    if(!should_run) return;
    assert(pp == _this);

    if(status < 0) {
        _this->mp_proxy->reject_connection(_this->m_id, NEW_CONNECTION_REPLY::CONNECT_FAIL);
        return;
    }
    _this->mp_proxy->accept_connection(_this->m_id);
    _this->__start_net_to_user();
} //}

void ServerToNetConnection::tcp2net_alloc_callback(uv_handle_t* req, size_t suggested_size, uv_buf_t* buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    buf->base = (char*)malloc(suggested_size);
    buf->len  = suggested_size;
    return;
} //}
void ServerToNetConnection::tcp2net_read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    ServerToNetConnection* _this = static_cast<decltype(_this)>(uv_handle_get_data((uv_handle_t*)stream));
    assert(_this);

    if(nread <= 0) {
        free(buf->base);
        _this->close();
        return;
    }

    ROBuf bufx(buf->base, nread, 0, free);
    _this->_write_to_user(bufx);
    return;
} //}

void ServerToNetConnection::__start_net_to_user() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_net_tcp_start_read == false);
    uv_read_start((uv_stream_t*)this->mp_tcp, 
            ServerToNetConnection::tcp2net_alloc_callback,
            ServerToNetConnection::tcp2net_read_callback);
    this->m_net_tcp_start_read = true;
} //}

void ServerToNetConnection::_write_to_user(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->mp_tcp != nullptr);
    this->m_net_to_user_buffer += buf.size();
    auto ptr = new UVC::ServerToNetConnection$_write_to_user$write(this->mp_proxy, this);
    this->mp_proxy->callback_insert(ptr, this);
    this->mp_proxy->write(this->m_id, buf, ServerToNetConnection::_write_to_user_callback, ptr);

    if(this->m_net_to_user_buffer > PROXY_MAX_BUFFER_SIZE) {
        uv_read_stop((uv_stream_t*)this->mp_tcp);
        this->m_net_tcp_start_read = false;
    }
} //}
void ServerToNetConnection::_write_to_user_callback(bool should_run, int status, ROBuf* buf, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    auto buf_size = buf->size();
    delete buf;

    UVC::ServerToNetConnection$_write_to_user$write* msg = 
        dynamic_cast<decltype(msg)>(static_cast<UVC::UVCBaseServer*>(data));
    assert(msg);
    auto proxy = msg->_proxy;
    auto _this = msg->_this;
    delete msg;

    auto pp = proxy->callback_remove(msg);
    if(pp == nullptr) should_run = false;
    assert(pp == _this);

    if(!should_run) return;

    _this->m_net_to_user_buffer -= buf_size;

    if(status < 0) {
        _this->close();
        return;
    }

    if(_this->m_net_to_user_buffer < PROXY_MAX_BUFFER_SIZE && _this->m_net_tcp_start_read == false)
        _this->__start_net_to_user();
} //}

void ServerToNetConnection::PushData(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    this->m_user_to_net_buffer += buf.size();
    uv_buf_t* bufx = new uv_buf_t();
    bufx->base = buf.__base();
    bufx->len = buf.size();
    uv_write_t* req = new uv_write_t();
    auto ptr = new UVC::ServerToNetConnection$PushData$uv_write(this->mp_proxy, this, new ROBuf(buf), bufx);
    this->mp_proxy->callback_insert(ptr, this);
    uv_req_set_data((uv_req_t*)req, ptr);

    uv_write(req, (uv_stream_t*)this->mp_tcp, bufx, 1, ServerToNetConnection::tcp2net_write_callback);

    if(this->m_user_to_net_buffer > PROXY_MAX_BUFFER_SIZE) {
        // TODO send a packet to inform client stop read the socket
        this->m_inform_client_stop_read = true;
        return;
    }
} //}
void ServerToNetConnection::tcp2net_write_callback(uv_write_t* req, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::ServerToNetConnection$PushData$uv_write* msg = 
        dynamic_cast<decltype(msg)>(static_cast<UVC::UVCBaseServer*>(uv_req_get_data((uv_req_t*)req)));
    auto _this = msg->_this;
    auto rbuf = msg->_robuf;
    auto uv_buf = msg->_uv_buf;
    auto proxy = msg->_proxy;
    bool should_run = msg->should_run;
    size_t buf_size = uv_buf->len;
    delete msg;
    delete req;
    delete uv_buf;
    delete rbuf;

    auto pp = proxy->callback_remove(msg);
    if(pp == nullptr) should_run = false;

    if(!should_run) return;

    assert(pp == _this);

    _this->m_user_to_net_buffer -=  buf_size;
    if(status < 0) {
        _this->close();
        return;
    }

    if(_this->m_user_to_net_buffer < PROXY_MAX_BUFFER_SIZE && _this->m_inform_client_stop_read) {
        // TODO send back a packet inform client continue to read the socket
        _this->m_inform_client_stop_read = false;
    }
} //}

void ServerToNetConnection::close() //{
{
    __logger->debug("call %s", FUNCNAME);
    if(this->m_net_tcp_start_read)
        uv_read_stop((uv_stream_t*)this->mp_tcp);
    if(this->mp_tcp != nullptr) {
        uv_close((uv_handle_t*)this->mp_tcp, delete_closed_handle<decltype(this->mp_tcp)>);
        this->mp_tcp = nullptr;
    }
    this->mp_proxy->remove_connection(this->m_id, this);
} //}

ServerToNetConnection::~ServerToNetConnection() {}
//}

}

