#include "../include/kclient.h"
#include "../include/config.h"
#include "../include/socks5.h"
#include "../include/uv_callback_data.h"

#include <tuple>
#include <vector>
#include <ostream>


namespace KProxyClient {

using Logger::logger;

static void malloc_cb(uv_handle_t*, size_t suggested_size, uv_buf_t* buf) //{
{
    buf->base = (char*)malloc(suggested_size);
    buf->len  = suggested_size;
} //}
static void delete_closed_handle(uv_handle_t* h) {delete h;}

//                  class Socks5Auth                     //{
Socks5Auth::Socks5Auth(Server* server, uv_tcp_t* client, ClientConfig* config, finish_cb cb, void* data) //{
{
    __logger->debug("Socks5Auth::Socks5Auth() new socks5 authentication session");
    this->mp_server = server;
    this->m_state = SOCKS5_INIT;
    this->mp_loop = uv_handle_get_loop((uv_handle_t*)client);
    this->mp_client = client;
    this->mp_config = config;
    this->m_remain = ROBuf();
    this->m_data = data;

    this->m_servername = "";
    this->m_port = 80;

    this->m_cb = cb;
    this->m_client_read_start = true;
    
    this->setup_uv_tcp_data();
    uv_read_start((uv_stream_t*)this->mp_client, malloc_cb, Socks5Auth::read_callback);
} //}

void Socks5Auth::setup_uv_tcp_data() //{
{
    auto ptr = new UVC::Socks5Auth$uv_read_start(this->mp_server, this); // FIXME
    uv_handle_set_data((uv_handle_t*)this->mp_client, ptr);
    this->mp_server->callback_insert(ptr);
} //}
void Socks5Auth::clean_uv_tcp_data() //{
{
    UVC::Socks5Auth$uv_read_start* _data =
        dynamic_cast<decltype(_data)>(static_cast<UVC::UVCBaseClient*>(uv_handle_get_data((uv_handle_t*)this->mp_client)));
    _data->_server->callback_remove(_data);
    delete _data;
    uv_handle_set_data((uv_handle_t*)this->mp_client, nullptr);
} //}

void Socks5Auth::return_to_server() //{ 
{
    __logger->debug("call Socks5Auth::return_to_server()");
    if(m_client_read_start) {
        uv_read_stop((uv_stream_t*)this->mp_client);
        this->m_client_read_start = false;
    }
    this->clean_uv_tcp_data();
    this->m_cb(0, this, this->m_servername, this->m_port, this->mp_client, this->m_data);
} //}
void Socks5Auth::try_to_build_connection() //{
{
    __logger->debug("Socks5Auth::try_to_build_connection() -> try to build a connection to server");
    assert(this->m_state == SOCKS5_FINISH);
    if(m_client_read_start) {
        uv_read_stop((uv_stream_t*)this->mp_client);
        this->m_client_read_start = false;
    }
    this->m_cb(0, this, this->m_servername, this->m_port, nullptr, this->m_data);
} //}
void Socks5Auth::close_this_with_error() //{
{
    __logger->debug("Socks5Auth::close_this_with_error()");
    this->m_state = SOCKS5_ERROR;
    if(m_client_read_start) {
        uv_read_stop((uv_stream_t*)this->mp_client);
        this->m_client_read_start = false;
    }
    this->clean_uv_tcp_data();
    this->m_cb(-1, this, this->m_servername, this->m_port, this->mp_client, this->m_data);
} //}

void Socks5Auth::read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    __logger->debug("call Socks5Auth::read_callback(0x%lx, %d, 0x%lx)", (long)stream, (int)nread, (long)buf);
    UVC::Socks5Auth$uv_read_start* _data =
        dynamic_cast<decltype(_data)>(static_cast<UVC::UVCBaseClient*>(uv_handle_get_data((uv_handle_t*)stream)));
    assert(_data);
    if(nread == 0) {
        return;
    }
    if(nread < 0) {
        _data->_this->m_state = SOCKS5_ERROR;
        _data->_this->return_to_server();
        return;
    }
    ROBuf bufx = ROBuf(buf->base, nread, 0, free);
    _data->_this->dispatch_data(bufx);
} //}

void Socks5Auth::dispatch_data(ROBuf buf) //{
{
    __logger->debug("call Socks5Auth::dispatch_data(buf.size()=%d)", buf.size());
    switch (this->m_state) {
        case SOCKS5_INIT: {
            auto x = parse_client_hello(this->m_remain, buf);
            bool finished;
            __client_selection_msg msg;
            ROBuf remain;
            std::tie(finished, msg, remain) = x;
            this->m_remain = remain;
            if(finished) {
                if(msg.m_version != 0x5) { // inform client TODO
                    return this->close_this_with_error();
                }
                socks5_authentication_method method = SOCKS5_AUTH_NO_ACCEPTABLE;
                for(auto& i: msg.m_methods) {
                    if(method == SOCKS5_AUTH_NO_ACCEPTABLE && i == SOCKS5_AUTH_NO_REQUIRED && 
                       this->mp_config->Policy().m_method == SOCKS5_NO_REQUIRED)
                        method = (socks5_authentication_method)i;
                    if(i == SOCKS5_AUTH_USERNAME_PASSWORD) 
                        method = (socks5_authentication_method)i;
                }
                this->m_state = SOCKS5_ID;
                if(method == SOCKS5_AUTH_NO_REQUIRED) this->m_state = SOCKS5_METHOD;
                this->__send_selection_method(method);
            }
            break;}
        case SOCKS5_ID: { // without debug, because chrome socks5 client dones't support username and password
            auto x = parse_username_authentication(this->m_remain, buf);
            bool finished;
            __socks5_username_password msg;
            ROBuf buf;
            std::tie(finished, msg, buf) = x;
            this->m_remain = buf;
            if(finished) {
                if(msg.m_version != 0x5) {
                    // TODO inform error
                    this->close_this_with_error();
                    break;
                }
                uint8_t status = -1;
                if(this->mp_config->validateUser(msg.m_username, msg.m_password)) {
                    status = 0;
                    this->m_state = SOCKS5_METHOD;
                }
                this->__send_auth_status(status);
            }
            break;
        }
        case SOCKS5_METHOD: {
            auto x = parse_client_request(this->m_remain, buf);
            bool finished, error;
            __client_request_msg msg;
            ROBuf remain;
            std::tie(finished, msg, remain, error) = x;
            this->m_remain = remain;
            if(error) {
                // TODO inform error
                this->close_this_with_error();
                break;
            }
            if(finished) {
                if(msg.m_version  != 0x5 ||
                   msg.m_command != SOCKS5_CMD_CONNECT ||
                   (msg.m_addr_type != SOCKS5_ADDR_IPV4 && msg.m_addr_type != SOCKS5_ADDR_DOMAIN)) {
                    // TODO inform error
                    this->close_this_with_error();
                    break;
                }
                this->m_servername = msg.m_addr;
                this->m_port = msg.m_port;
                this->m_state = SOCKS5_FINISH;
                this->try_to_build_connection(); // TODO
            }
            break;
        }
        case SOCKS5_FINISH:
        case SOCKS5_ERROR:
            assert(false && "bug");
            break;
    }
} //}

void Socks5Auth::__send_selection_method(socks5_authentication_method method) //{
{
    __logger->debug("send selection mothod: %d", (uint8_t)method);
    __server_selection_msg* msg = new __server_selection_msg();
    msg->m_version = 0x5;
    msg->m_method = method;
    uv_buf_t* buf = new uv_buf_t();
    buf->base = (char*)msg;
    buf->len = sizeof(__server_selection_msg);

    uv_write_t* req = new uv_write_t();
    auto ptr = new UVC::Socks5Auth$__send_selection_method$uv_write(this->mp_server, this, buf);
    uv_req_set_data((uv_req_t*)req, ptr);
    this->mp_server->callback_insert(ptr);
    uv_write(req, (uv_stream_t*)this->mp_client, buf, 1, Socks5Auth::write_callback_hello);
} //}
void Socks5Auth::__send_auth_status(uint8_t status) //{
{
    __logger->debug("send authenticate status: %d", status);
    __socks5_user_authentication_reply* msg = new __socks5_user_authentication_reply();
    msg->m_version = 0x5;
    msg->m_status = status;
    uv_buf_t* buf = new uv_buf_t();
    buf->base = (char*)msg;
    buf->len = sizeof(__socks5_user_authentication_reply);

    uv_write_t* req = new uv_write_t();
    auto ptr = new UVC::Socks5Auth$__send_auth_status$uv_write(this->mp_server, this, buf);
    uv_req_set_data((uv_req_t*)req, ptr);
    this->mp_server->callback_insert(ptr);
    uv_write(req, (uv_stream_t*)this->mp_client, buf, 1, Socks5Auth::write_callback_id);
} //}
void Socks5Auth::__send_reply(uint8_t reply) //{
{
    __logger->debug("send reply for client request, status: %d, remain_size: %d", reply, this->m_remain.size());
    if(this->m_client_read_start) {
        uv_read_stop((uv_stream_t*)this->mp_client);
    }
    this->m_client_read_start = false;
    __server_reply_msg msg;
    msg.m_version = 0x5;
    msg.m_reply = (socks5_reply_type)reply;
    msg.m_reserved = 0;
    msg.m_addr_type = SOCKS5_ADDR_IPV4;
    uint32_t ipv4addr;
    char* bufx = nullptr;
    size_t size = 0;
    if(str_to_ip4(this->m_servername.c_str(), &ipv4addr)) {
        size = 10;
        bufx = (char*)malloc(size);
        memcpy(bufx, &msg, 4);
        *(uint32_t*)(bufx + 4) = ipv4addr;
        *(uint16_t*)(bufx + 8) = this->m_port; // FIXME
    } else {
        size = this->m_servername.length() + 7;
        bufx = (char*)malloc(size);
        msg.m_addr_type = SOCKS5_ADDR_DOMAIN;
        memcpy(bufx, &msg, 4);
        *(bufx + 4) = this->m_servername.size();
        memcpy(bufx + 5, this->m_servername.c_str(), this->m_servername.size());
        *(uint16_t*)(bufx + (size - 2)) = this->m_port; // FIXME
    }
    uv_buf_t* buf = new uv_buf_t();
    buf->base = (char*)bufx;
    buf->len = size;

    uv_write_t* req = new uv_write_t();
    auto ptr = new UVC::Socks5Auth$__send_reply$uv_write(this->mp_server, this, buf);
    uv_req_set_data((uv_req_t*)req, ptr);
    this->mp_server->callback_insert(ptr);
    uv_write(req, (uv_stream_t*)this->mp_client, buf, 1, Socks5Auth::write_callback_reply);
} //}

void Socks5Auth::write_callback_hello(uv_write_t* req, int status) //{
{
    UVC::Socks5Auth$__send_selection_method$uv_write* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    assert(x);
    x->_server->callback_remove(x);
    Socks5Auth* _this = x->_this;
    uv_buf_t* buf = x->uv_buf;
    bool should_run = x->should_run;
    delete x;
    delete (__server_selection_msg*)buf->base;
    delete buf;
    if(status != 0 && should_run) _this->return_to_server();
} //}
void Socks5Auth::write_callback_id(uv_write_t* req, int status) //{
{
    UVC::Socks5Auth$__send_auth_status$uv_write* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    assert(x);
    x->_server->callback_remove(x);
    Socks5Auth* _this = x->_this;
    uv_buf_t* buf = x->uv_buf;
    bool should_run = x->should_run;
    delete x;
    delete (__socks5_user_authentication_reply*)buf->base;
    delete buf;
    if(status != 0 && should_run) _this->return_to_server();
} //}
void Socks5Auth::write_callback_reply(uv_write_t* req, int status) //{
{
    UVC::Socks5Auth$__send_reply$uv_write* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    assert(x);
    x->_server->callback_remove(x);
    Socks5Auth* _this = x->_this;
    uv_buf_t* buf = x->uv_buf;
    bool should_run = x->should_run;
    delete x;
    free(buf->base);
    delete buf;
    if(should_run) {
        if(status != 0 || _this->m_remain.size() != 0)
            _this->close_this_with_error();
        else 
            // this does't mean everything is fine, it's possible relay connection doesn't establish
            _this->return_to_server(); 
    }
} //}

void Socks5Auth::close() //{
{
    this->close_this_with_error();
} //}
//}


//                class Server                                //{
Server::Server(uv_loop_t* loop, const std::string& config_file) //{
{
    this->mp_uv_loop = loop;
    this->m_config = new ClientConfig(this->mp_uv_loop, config_file.c_str());
    this->bind_addr = 0;
    this->bind_port = 1111;
    this->mp_uv_tcp = new uv_tcp_t();
    uv_tcp_init(this->mp_uv_loop, this->mp_uv_tcp);
    uv_handle_set_data((uv_handle_t*)this->mp_uv_tcp, new UVC::KProxyClient$Server$uv_listen(this));
} //}

Server::~Server() //{
{
     UVC::KProxyClient$Server$uv_listen* x = 
        dynamic_cast<UVC::KProxyClient$Server$uv_listen*>(static_cast<UVC::UVCBaseClient*>(uv_handle_get_data((uv_handle_t*)this->mp_uv_tcp)));
     delete x;

     delete this->m_config;
     delete this->mp_uv_tcp;
} //}

void Server::on_config_load(int error, void* data) //{
{
    Server* _this = (Server*) data;
    if(error > 0) {
        logger->error("load config file fail");
        exit(1);
    }
    _this->bind_addr = _this->m_config->BindAddr();
    _this->bind_port = _this->m_config->BindPort();
    _this->__listen();
} //}
int Server::__listen() //{ 
{
    logger->debug("call __listen()");
    sockaddr_in addr;

    uint32_t network_order_addr = this->bind_addr;

    uv_ip4_addr(ip4_to_str(network_order_addr), this->bind_port, &addr);
    int s = uv_tcp_bind(this->mp_uv_tcp, (sockaddr*)&addr, 0);
    if(s != 0) {
        logger->error("bind error %s:%d", ip4_to_str(network_order_addr), this->bind_port);
        return s;
    }
    s = uv_listen((uv_stream_t*)this->mp_uv_tcp, MAX_LISTEN, Server::on_connection);
    if(s != 0) {
        logger->error("listen error %s:%d", ip4_to_str(network_order_addr), this->bind_port);
        return s;
    }
    this->run___ = true;
    logger->debug("listen at %s:%d", ip4_to_str(network_order_addr), this->bind_port);
    return 0;
} //}

int Server::listen() //{ 
{
    logger->debug("call Server::listen()");
    this->m_config->loadFromFile(Server::on_config_load, this);
    return 0;
} //}

void Server::close() //{
{
    assert(this->exit__ == false);
    this->exit__ = true;
    uv_close((uv_handle_t*)this->mp_uv_tcp, nullptr); // block api

    std::cout << "auths: " << this->m_auths.size() << std::endl;
    auto copy_auth = this->m_auths;
    for(auto& auth: copy_auth)
        auth.first->close();

    std::cout << "relay: " << this->m_relay.size() << std::endl;
    auto copy_relay = this->m_relay;
    for(auto& relay: copy_relay)
        relay->close();

    std::cout << "waiting callbacks: " << this->m_callback_list.size() << std::endl;
    for(auto& data: this->m_callback_list)
        data->should_run = false;

    this->try_close();
    return;
} //}

void Server::try_close() //{
{
    if(this->exit__ == false) return;
    if(this->m_auths.size() == 0 && this->m_relay.size() == 0 && this->m_callback_list.size() == 0) this->run___ = false;
} //}

/** connection callback function */
void Server::on_connection(uv_stream_t* stream, int status) //{
{
    __logger->debug("call Server::on_connection()");
    if(status < 0) {
        __logger->warn("new connection error");
        return;
    }

    UVC::KProxyClient$Server$uv_listen* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_handle_get_data((uv_handle_t*)stream)));
    assert(x);
    Server* _this = x->_this;
    __logger->debug("connections: %d", _this->m_auths.size() + _this->m_relay.size());

    if(_this->exit__) return;

    uv_tcp_t* client = new uv_tcp_t();
    uv_tcp_init(x->_this->mp_uv_loop, client);

    if(uv_accept(stream, (uv_stream_t*)client) < 0) {
        __logger->warn("accept new connection error");
        uv_close((uv_handle_t*)client, delete_closed_handle);
        return;
    }
    Socks5Auth* auth = new Socks5Auth(_this, client, _this->m_config, Server::on_authentication, _this);
    _this->m_auths[auth] = std::make_tuple(true, nullptr); 
} //}

void Server::on_authentication(int status, Socks5Auth* self_ref, 
        const std::string& addr, uint16_t port,
        uv_tcp_t* con, void* data) //{
{
    Server* _this = (Server*)data;
    __logger->debug("call [static] Server::on_authentication(), connections: %d", _this->m_auths.size() + _this->m_relay.size());
    assert(_this->m_auths.find(self_ref) != _this->m_auths.end());
    if(con == nullptr) {     // 1. connect
        assert(status == 0);
        _this->dispath_base_on_addr(addr, port, self_ref);
    } else {
        if(status < 0) { // 2. delete
            uv_close((uv_handle_t*)con, delete_closed_handle);
            delete self_ref;
            auto mm = _this->m_auths[self_ref];
            if(std::get<0>(mm)) { // bypass
                if(std::get<1>(mm) != nullptr)
                    delete (RelayConnection*)std::get<1>(mm);
            } else {
                assert(false && "bug...");
            }
            _this->m_auths.erase(_this->m_auths.find(self_ref));
            _this->try_close();
            return;
        } else { // 3. transfer connection to relay
            delete self_ref;
            _this->redispatch(con, self_ref);
            return;
        }
    }
} //}

void Server::dispath_base_on_addr(const std::string& addr, uint16_t port, Socks5Auth* socks5) //{
{
    this->dispath_bypass(addr, port, socks5);
} //}

void Server::dispath_bypass(const std::string& addr, uint16_t port, Socks5Auth* socks5) //{
{
    RelayConnection* relay = new RelayConnection(this, this->mp_uv_loop, nullptr, addr, port);
    this->m_auths[socks5] = std::make_tuple(true, relay);
    relay->connect(socks5);
} //}

void Server::redispatch(uv_tcp_t* client_tcp, Socks5Auth* socks5) //{
{
    auto ff = this->m_auths.find(socks5);
    assert(ff != this->m_auths.end());
    if(std::get<0>(ff->second)) {
        RelayConnection* rl = (decltype(rl))std::get<1>(ff->second);
        this->m_auths.erase(ff);
        this->m_relay.insert(rl);
        rl->run(client_tcp);
    } else {
        assert(false && "bugggg");
    }
} //}

void Server::close_relay(RelayConnection* relay) //{
{
    __logger->debug("connections: %d", this->m_auths.size() + this->m_relay.size());
    assert(this->m_relay.find(relay) != this->m_relay.end());
    this->m_relay.erase(this->m_relay.find(relay));
    delete relay;
    this->try_close();
} //}

void Server::callback_insert(UVC::UVCBaseClient* ptr) //{
{
    assert(ptr != nullptr);
    assert(this->m_callback_list.find(ptr) == this->m_callback_list.end());
    this->m_callback_list.insert(ptr);
} //}

void Server::callback_remove(UVC::UVCBaseClient* ptr) //{
{
    assert(ptr != nullptr);
    assert(this->m_callback_list.find(ptr) != this->m_callback_list.end());
    this->m_callback_list.erase(this->m_callback_list.find(ptr));
    __logger->debug("waiting callbacks: %ld, relayconnections: %ld, authconnections: %ld", 
            this->m_callback_list.size(), this->m_relay.size(), this->m_auths.size());
    this->try_close();
} //}
//}


//                class RelayConnection                       //{
RelayConnection::RelayConnection(Server* kserver, uv_loop_t* loop, uv_tcp_t* tcp_client, const std::string& server, uint16_t port) //{
{
    __logger->debug("RelayConnection() to %s:%d", server.c_str(), k_ntohs(port));
    assert(tcp_client == nullptr);
    this->m_kserver = kserver;
    this->mp_loop = loop;
    this->mp_tcp_client = tcp_client;
    this->m_in_buffer = 0;
    this->m_out_buffer = 0;
    this->mp_tcp_server = nullptr;
    this->m_server = server;
    this->m_port = port;
    this->m_error = false;

    this->m_client_start_read = false;
    this->m_server_start_read = false;
}
//}

void RelayConnection::connect(Socks5Auth* socks5) //{
{
    __logger->debug("call RelayConnection::connect()");
    uint32_t addr_ipv4;

    if(str_to_ip4(this->m_server.c_str(), &addr_ipv4)) {
        struct addrinfo info;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = k_ntohs(this->m_port);
        addr.sin_addr.s_addr = k_ntohl(addr_ipv4);
        info.ai_family = AF_INET;
        info.ai_addrlen = sizeof(sockaddr_in); // FIXME ??
        info.ai_canonname = nullptr;
        info.ai_next = nullptr;
        info.ai_flags = 0;
        info.ai_addr = (sockaddr*)&addr;

        uv_getaddrinfo_t req;
        auto ptr = new UVC::RelayConnection$connect$uv_getaddrinfo(this->m_kserver, false, this, socks5);
        uv_req_set_data((uv_req_t*)&req, ptr);
        this->m_kserver->callback_insert(ptr);
        RelayConnection::getaddrinfo_cb(&req, 0, &info);
    } else {
        struct addrinfo hints;
        hints.ai_family = AF_INET;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = 0;

        uv_getaddrinfo_t* p_req = new uv_getaddrinfo_t();
        auto ptr = new UVC::RelayConnection$connect$uv_getaddrinfo(this->m_kserver, true, this, socks5);
        uv_req_set_data((uv_req_t*)p_req, ptr);
        this->m_kserver->callback_insert(ptr);

        uv_getaddrinfo(this->mp_loop, p_req, RelayConnection::getaddrinfo_cb, this->m_server.c_str(), "80", &hints);
    }
} //}

void RelayConnection::run(uv_tcp_t* client_tcp) //{
{
    __logger->debug("call RelayConnection::run()");
    this->mp_tcp_client = client_tcp;
    uv_handle_set_data((uv_handle_t*)this->mp_tcp_client, this);
    if(this->mp_tcp_server != nullptr)
        this->__start_relay();
    else
        this->close();
} //}

void RelayConnection::close() //{
{
    __logger->debug("call RelayConnection::close(this=0x%lx)", (long)this);
    this->m_error = true;
    if(this->m_server_start_read) {
        uv_read_stop((uv_stream_t*)this->mp_tcp_server);
        this->m_server_start_read = false;
    }
    if(this->m_client_start_read) {
        uv_read_stop((uv_stream_t*)this->mp_tcp_client);
        this->m_client_start_read = false;
    }
    __logger->debug("0x%lx -- buf1: %d, buf2: %d", (long)this, this->m_in_buffer, this->m_out_buffer);
    if(this->m_in_buffer == 0 && this->m_out_buffer == 0) {
        if(this->mp_tcp_server != nullptr) {
            uv_close((uv_handle_t*)this->mp_tcp_server, delete_closed_handle);
            this->mp_tcp_server = nullptr;
        }
        uv_close((uv_handle_t*)this->mp_tcp_client, delete_closed_handle);
        this->mp_tcp_client = nullptr;
        return this->m_kserver->close_relay(this);
    }
} //}

void RelayConnection::__connect_to(const sockaddr* addr, Socks5Auth* socks5) //{
{
    __logger->debug("call RelayConnection::__connect_to(this=0x%lx)", (long)this);

    uv_connect_t* req = new uv_connect_t();
    auto ptr = new UVC::RelayConnection$__connect_to$uv_tcp_connect(this->m_kserver, this, socks5);
    uv_req_set_data((uv_req_t*)req, ptr);
    this->m_kserver->callback_insert(ptr);

    uv_tcp_t* tcp = new uv_tcp_t();
    uv_tcp_init(this->mp_loop, tcp);
    this->mp_tcp_server = tcp;
    uv_handle_set_data((uv_handle_t*)this->mp_tcp_server, this); // FIXME

    // TODO set a timeout
    uv_tcp_connect(req, tcp, addr, RelayConnection::connect_server_cb);
} //}

// static
void RelayConnection::getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) //{
{
    __logger->debug("call RelayConnection::getaddrinfo_callback()");
    struct addrinfo *a;
    struct sockaddr_in* m;

    UVC::RelayConnection$connect$uv_getaddrinfo* msg =
        dynamic_cast<decltype(msg)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    msg->_server->callback_remove(msg);
    bool clean = msg->is_uv;
    RelayConnection* _this = msg->_this;
    Socks5Auth* socks5 = msg->_socks5;
    bool should_run = msg->should_run;
    if(clean) delete req;
    delete msg;

    if(!should_run) {
        uv_freeaddrinfo(res);
        return;
    }

    if(status < 0) {
        __logger->warn("dns query fail");
        // TODO send a close packet
        if(clean) uv_freeaddrinfo(res);
        return socks5->send_reply(SOCKS5_REPLY_HOST_UNREACHABLE);
    }
    for(a = res; a != nullptr; a = a->ai_next) {
        if(sizeof(struct sockaddr_in) != a->ai_addrlen) {
            __logger->debug("query dns get an address that isn't ipv4 address");
            continue;
        } else break;
    }
    if(a == nullptr) {
        logger->warn("query dns doesn't get an ipv4 address");
        // TODO send a close packet
        if(clean) uv_freeaddrinfo(res);
        return socks5->send_reply(SOCKS5_REPLY_ADDRESSS_TYPE_NOT_SUPPORTED);
    }
    m = (struct sockaddr_in*)a->ai_addr; // FIXME
    m->sin_port = _this->m_port;
    _this->__connect_to((sockaddr*)m, socks5);
    if(clean) uv_freeaddrinfo(res);
} //}

void RelayConnection::connect_server_cb(uv_connect_t* req, int status) //{
{
    // FIXME this function will still call when server is closed
    __logger->debug("call RelayConnection::connect_server_cb() callback");
    UVC::RelayConnection$__connect_to$uv_tcp_connect* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    x->_server->callback_remove(x);
    RelayConnection* _this = x->_this;
    Socks5Auth* socks5 = x->_socks5;
    bool should_run = x->should_run;
    delete x;
    delete req;
    if(should_run) {
        if(status != 0) {
            __logger->debug("RelayConnection::conenct_sesrver_cb() fail");
            uv_close((uv_handle_t*) _this->mp_tcp_server, delete_closed_handle);
            _this->mp_tcp_server = nullptr;
            return socks5->send_reply(SOCKS5_REPLY_CONNECTION_REFUSED);
        } else {
            return socks5->send_reply(SOCKS5_REPLY_SUCCEEDED);
        }
    }
} //}

void RelayConnection::__start_relay() //{
{
    __logger->debug("call RelayConnection::__start_relay()");
    this->__relay_client_to_server();
    this->__relay_server_to_client();
} //}

void RelayConnection::__relay_client_to_server() //{
{
    __logger->debug("call RelayConnection::__relay_client_to_server()");
    assert(this->m_client_start_read == false);
    uv_read_start((uv_stream_t*)this->mp_tcp_client, 
            malloc_cb, 
            RelayConnection::client_read_cb);
    this->m_client_start_read = true;
} //}
void RelayConnection::__relay_server_to_client() //{
{
    __logger->debug("call RelayConnection::__relay_server_to_client()");
    assert(this->m_server_start_read == false);
    uv_read_start((uv_stream_t*)this->mp_tcp_server, 
            malloc_cb, 
            RelayConnection::server_read_cb);
    this->m_server_start_read = true;
} //}

void RelayConnection::client_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    __logger->debug("call RelayConnection::client_read_cb() callback");
    if(nread == 0) return;
    RelayConnection* _this = (RelayConnection*)uv_handle_get_data((uv_handle_t*)stream);
    if(nread < 0) {
        _this->close();
        return;
    }
    uv_buf_t* bufx = new uv_buf_t();
    bufx->base = buf->base;
    bufx->len  = nread;
    uv_write_t* req = new uv_write_t();
    auto ptr = new UVC::RelayConnection$xxxx_read_cb$uv_write(_this->m_kserver, _this, bufx);
    uv_req_set_data((uv_req_t*)req, ptr);
    _this->m_kserver->callback_insert(ptr);
    _this->m_out_buffer += nread;
    uv_write(req, (uv_stream_t*)_this->mp_tcp_server, bufx, 1, RelayConnection::server_write_cb);

    if(_this->m_out_buffer > RELAY_MAX_BUFFER_SIZE) {
        uv_read_stop(stream);
        _this->m_client_start_read = false;
    }
} //}
void RelayConnection::server_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    __logger->debug("call RelayConnection::server_read_cb() callback");
    if(nread == 0) return;
    RelayConnection* _this = (RelayConnection*)uv_handle_get_data((uv_handle_t*)stream);
    if(nread < 0) {
        _this->close();
        return;
    }
    uv_buf_t* bufx = new uv_buf_t();
    bufx->base = buf->base;
    bufx->len  = nread;
    uv_write_t* req = new uv_write_t();
    auto ptr = new UVC::RelayConnection$xxxx_read_cb$uv_write(_this->m_kserver, _this, bufx);
    uv_req_set_data((uv_req_t*)req, ptr);
    _this->m_kserver->callback_insert(ptr);
    _this->m_in_buffer += nread;
    uv_write(req, (uv_stream_t*)_this->mp_tcp_client, bufx, 1, RelayConnection::client_write_cb);

    if(_this->m_in_buffer > RELAY_MAX_BUFFER_SIZE) {
        uv_read_stop(stream);
        _this->m_server_start_read = false;
    }
} //}

void RelayConnection::server_write_cb(uv_write_t* req, int status) //{
{
    __logger->debug("call RelayConnection::server_write_cb() callback");
    UVC::RelayConnection$xxxx_read_cb$uv_write* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    x->_server->callback_remove(x);
    RelayConnection* _this = x->_this;
    const uv_buf_t* buf = x->uv_buf;
    bool should_run = x->should_run;
    delete x;

    if(should_run)
        _this->m_out_buffer -= buf->len;
    free(buf->base);
    delete buf;

    if(!should_run) return;

    if(status != 0 || _this->m_error) {
        _this->m_error = true;
        _this->close();
        return;
    }

    if(!_this->m_client_start_read && _this->m_out_buffer < RELAY_MAX_BUFFER_SIZE)
        _this->__relay_client_to_server();
} //}
void RelayConnection::client_write_cb(uv_write_t* req, int status) //{
{
    __logger->debug("call RelayConnection::client_write_cb() callback");
    UVC::RelayConnection$xxxx_read_cb$uv_write* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    x->_server->callback_remove(x);
    RelayConnection* _this = x->_this;
    const uv_buf_t* buf = x->uv_buf;
    bool should_run = x->should_run;
    delete x;

    if(should_run)
        _this->m_in_buffer -= buf->len;
    free(buf->base);
    delete buf;

    if(!should_run) return;

    if(status != 0 || _this->m_error) {
        _this->m_error = true;
        _this->close();
        return;
    }

    if(!_this->m_server_start_read && _this->m_in_buffer < RELAY_MAX_BUFFER_SIZE)
        _this->__relay_server_to_client();
} //}

RelayConnection::~RelayConnection() //{
{
    assert(this->mp_tcp_client == nullptr);
    if(this->mp_tcp_server != nullptr)
        uv_close((uv_handle_t*)this->mp_tcp_server, delete_closed_handle);
} //}
//}

}

