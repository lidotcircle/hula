#include "../include/kclient.h"
#include "../include/config.h"
#include "../include/socks5.h"
#include "../include/uv_callback_data.h"

#include <tuple>
#include <vector>
#include <ostream>

#define NEW_CONNECTION_TIMEOUT (3 * 2000)

namespace KProxyClient {

using Logger::logger;

static void malloc_cb(uv_handle_t*, size_t suggested_size, uv_buf_t* buf) //{
{
    buf->base = (char*)malloc(suggested_size);
    buf->len  = suggested_size;
} //}
template<typename T>
static void delete_closed_handle(uv_handle_t* h) {delete static_cast<T>(static_cast<void*>(h));}

//                  class Socks5Auth                     //{
Socks5Auth::Socks5Auth(Server* server, uv_tcp_t* client, ClientConfig* config, finish_cb cb, void* data) //{
{
    __logger->debug("call %s: new socks5 authentication session", FUNCNAME);
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
    __logger->debug("call %s", FUNCNAME);
    auto ptr = new UVC::Socks5Auth$uv_read_start(this->mp_server, this);
    uv_handle_set_data((uv_handle_t*)this->mp_client, ptr);
    this->mp_server->callback_insert(ptr);
} //}
void Socks5Auth::clean_uv_tcp_data() //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::Socks5Auth$uv_read_start* _data =
        dynamic_cast<decltype(_data)>(static_cast<UVC::UVCBaseClient*>(uv_handle_get_data((uv_handle_t*)this->mp_client)));
    _data->_server->callback_remove(_data);
    delete _data;
    uv_handle_set_data((uv_handle_t*)this->mp_client, nullptr);
} //}

void Socks5Auth::return_to_server() //{ 
{
    __logger->debug("call %s", FUNCNAME);
    if(m_client_read_start) {
        uv_read_stop((uv_stream_t*)this->mp_client);
        this->m_client_read_start = false;
    }
    this->clean_uv_tcp_data();
    this->m_cb(0, this, this->m_servername, this->m_port, this->mp_client, this->m_data);
} //}
void Socks5Auth::try_to_build_connection() //{
{
    __logger->debug("call %s: try to build a connection to server", FUNCNAME);
    assert(this->m_state == SOCKS5_FINISH);
    if(m_client_read_start) {
        uv_read_stop((uv_stream_t*)this->mp_client);
        this->m_client_read_start = false;
    }
    this->m_cb(0, this, this->m_servername, this->m_port, nullptr, this->m_data);
} //}
void Socks5Auth::close_this_with_error() //{
{
    __logger->debug("call %s", FUNCNAME);
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
    __logger->debug("call %s = (0x%lx, %d, 0x%lx)", FUNCNAME, (long)stream, (int)nread, (long)buf);
    UVC::Socks5Auth$uv_read_start* _data =
        dynamic_cast<decltype(_data)>(static_cast<UVC::UVCBaseClient*>(uv_handle_get_data((uv_handle_t*)stream)));
    assert(_data);
    if(nread == 0) {
        free(buf->base);
        return;
    }
    if(nread < 0) {
        free(buf->base);
        _data->_this->m_state = SOCKS5_ERROR;
        _data->_this->return_to_server();
        return;
    }
    ROBuf bufx = ROBuf(buf->base, nread, 0, free);
    _data->_this->dispatch_data(bufx);
} //}

void Socks5Auth::dispatch_data(ROBuf buf) //{
{
    __logger->debug("call %s = (buf.size()=%d)", FUNCNAME, buf.size());
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
    __logger->debug("call %s: send selection mothod: %d", FUNCNAME, (uint8_t)method);
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
    __logger->debug("call %s: send authenticate status: %d", FUNCNAME, status);
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
    __logger->debug("call %s, status: %d, remain_size: %d", FUNCNAME, reply, this->m_remain.size());
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
    auto ptr = new UVC::Socks5Auth$__send_reply$uv_write(this->mp_server, this, buf, reply);
    uv_req_set_data((uv_req_t*)req, ptr);
    this->mp_server->callback_insert(ptr);
    uv_write(req, (uv_stream_t*)this->mp_client, buf, 1, Socks5Auth::write_callback_reply);
} //}

void Socks5Auth::write_callback_hello(uv_write_t* req, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
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
    delete req;
    if(status != 0 && should_run) _this->return_to_server();
} //}
void Socks5Auth::write_callback_id(uv_write_t* req, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
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
    delete req;
    if(status != 0 && should_run) _this->return_to_server();
} //}
void Socks5Auth::write_callback_reply(uv_write_t* req, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::Socks5Auth$__send_reply$uv_write* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    assert(x);
    x->_server->callback_remove(x);
    Socks5Auth* _this = x->_this;
    uv_buf_t* buf = x->uv_buf;
    uint8_t reply = x->reply;
    bool should_run = x->should_run;
    delete x;
    free(buf->base);
    delete buf;
    delete req;
    if(should_run) {
        if(status != 0 || _this->m_remain.size() != 0 || reply != SOCKS5_REPLY_SUCCEEDED)
            _this->close_this_with_error();
        else 
            // this does't mean everything is fine, it's possible relay connection doesn't establish
            _this->return_to_server(); 
    }
} //}

void Socks5Auth::close() //{
{
    __logger->debug("call %s", FUNCNAME);
    this->close_this_with_error();
} //}
//}


//                class Server                                //{
Server::Server(uv_loop_t* loop, const std::string& config_file) //{
{
    __logger->debug("call %s", FUNCNAME);
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
    __logger->debug("call %s", FUNCNAME);
     UVC::KProxyClient$Server$uv_listen* x = 
        dynamic_cast<UVC::KProxyClient$Server$uv_listen*>(static_cast<UVC::UVCBaseClient*>(uv_handle_get_data((uv_handle_t*)this->mp_uv_tcp)));
     delete x;

     delete this->m_config;
     delete this->mp_uv_tcp;
} //}

/** connection callback function */
void Server::on_connection(uv_stream_t* stream, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    if(status < 0) {
        __logger->warn("new connection error");
        return;
    }

    UVC::KProxyClient$Server$uv_listen* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_handle_get_data((uv_handle_t*)stream)));
    assert(x);
    Server* _this = x->_this;

    if(_this->exit__) return;

    uv_tcp_t* client = new uv_tcp_t();
    uv_tcp_init(x->_this->mp_uv_loop, client);

    if(uv_accept(stream, (uv_stream_t*)client) < 0) {
        __logger->warn("accept new connection error");
        uv_close((uv_handle_t*)client, delete_closed_handle<decltype(client)>);
        return;
    }
    Socks5Auth* auth = new Socks5Auth(_this, client, _this->m_config, Server::on_authentication, _this);
    _this->m_auths[auth] = std::make_tuple(true, nullptr); 
} //}

void Server::on_authentication(int status, Socks5Auth* self_ref, 
        const std::string& addr, uint16_t port,
        uv_tcp_t* con, void* data) //{
{
    Server* _this = static_cast<Server*>(data);
    __logger->debug("call %s: connections: %d", FUNCNAME, _this->m_auths.size() + _this->m_relay.size());
    assert(_this->m_auths.find(self_ref) != _this->m_auths.end());
    if(con == nullptr) {     // 1. connect
        assert(status == 0);
        _this->dispatch_base_on_addr(addr, port, self_ref);
    } else {
        if(status < 0) { // 2. delete
            uv_close((uv_handle_t*)con, delete_closed_handle<decltype(con)>);
            delete self_ref;
            auto mm = _this->m_auths[self_ref];
            ClientConnection* cc = dynamic_cast<ClientConnection*>(std::get<1>(mm));
            RelayConnection*  cr = dynamic_cast<RelayConnection*>(std::get<1>(mm));
            if(std::get<0>(mm)) { // bypass
                assert(cr || cc == nullptr);
                if(cr) delete cr;
            } else { // proxy
                assert(cc || cr == nullptr);
                if(cc) delete cc; // TODO
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

void Server::on_config_load(int error, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
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
    logger->debug("call %s", FUNCNAME);
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

void Server::dispatch_base_on_addr(const std::string& addr, uint16_t port, Socks5Auth* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
//    this->dispatch_bypass(addr, port, socks5);
    this->dispatch_proxy(addr, port, socks5);
} //}
void Server::dispatch_bypass(const std::string& addr, uint16_t port, Socks5Auth* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    RelayConnection* relay = new RelayConnection(this, this->mp_uv_loop, nullptr, addr, port);
    this->m_auths[socks5] = std::make_tuple(true, relay);
    relay->connect(socks5);
} //}
void Server::dispatch_proxy(const std::string& addr, uint16_t port, Socks5Auth* socks5) //{
{
    __logger->debug("call %s = (%s, %d, 0x%lx)", FUNCNAME, addr.c_str(), port, (long)socks5);
    ConnectionProxy* pp = nullptr;
    for(auto& m: this->m_proxy) {
        if(!m->IsIdFull() && m->IsConnected()) {
            pp = m;
            break;
        }
    }

    if(pp == nullptr) {
        auto c = this->select_remote_serever();
        if(c == nullptr) {
            socks5->send_reply(SOCKS5_REPLY_SERVER_FAILURE);
            return;
        }
        pp = new ConnectionProxy(this->mp_uv_loop, this, c);
        this->m_proxy.insert(pp);
    }

    ClientConnection* con = new ClientConnection(this, this->mp_uv_loop, pp, addr, port, socks5);
    this->m_auths[socks5] = std::make_tuple(false, con);
    con->connect(socks5);
} //}

SingleServerInfo* Server::select_remote_serever() //{
{
    __logger->debug("call %s", FUNCNAME);
    for(auto& x: this->m_config->Servers())
        return &x;
    return nullptr;
} //}

void Server::redispatch(uv_tcp_t* client_tcp, Socks5Auth* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    auto ff = this->m_auths.find(socks5);
    assert(ff != this->m_auths.end());
    ClientConnection* cc = dynamic_cast<ClientConnection*>(std::get<1>(ff->second));
    RelayConnection*  cr = dynamic_cast<RelayConnection*> (std::get<1>(ff->second));
    if(std::get<0>(ff->second)) {
        assert(cr);
        this->m_auths.erase(ff);
        this->m_relay.insert(cr);
        cr->run(client_tcp);
    } else {
        assert(cc);
        this->m_auths.erase(ff);
        cc->run(client_tcp);
    }
} //}

void Server::try_close() //{
{
    __logger->debug("call %s", FUNCNAME);
    if(this->exit__ == false) return;

    if(this->m_auths.size() == 0 && 
       this->m_relay.size() == 0 && 
       this->m_proxy.size() == 0 && 
       this->m_callback_list.size() == 0) 
        this->run___ = false;
} //}

void Server::close_relay(RelayConnection* relay) //{
{
    __logger->debug("call %s, connections: %d", FUNCNAME, this->m_auths.size() + this->m_relay.size());
    assert(this->m_relay.find(relay) != this->m_relay.end());
    this->m_relay.erase(this->m_relay.find(relay));
    delete relay;
    this->try_close();
} //}

void Server::callback_insert(UVC::UVCBaseClient* ptr) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(ptr != nullptr);
    assert(this->m_callback_list.find(ptr) == this->m_callback_list.end());
    this->m_callback_list.insert(ptr);
} //}
void Server::callback_remove(UVC::UVCBaseClient* ptr) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(ptr != nullptr);
    assert(this->m_callback_list.find(ptr) != this->m_callback_list.end());
    this->m_callback_list.erase(this->m_callback_list.find(ptr));
    __logger->debug("waiting callbacks: %ld, relayconnections: %ld, authconnections: %ld", 
            this->m_callback_list.size(), this->m_relay.size(), this->m_auths.size());
    this->try_close();
} //}

int Server::listen() //{ 
{
    logger->debug("call %s", FUNCNAME);
    this->m_config->loadFromFile(Server::on_config_load, this);
    return 0;
} //}
void Server::close() //{
{
    __logger->debug("call %s", FUNCNAME);
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

    std::cout << "proxy: " << this->m_proxy.size() << std::endl;
    auto copy_proxy = this->m_proxy;
    for(auto& proxy: copy_proxy)
        proxy->close(ConnectionProxy::CLOSE_REQUIRED);

    std::cout << "waiting callbacks: " << this->m_callback_list.size() << std::endl;
    for(auto& data: this->m_callback_list)
        data->should_run = false;

    this->try_close();
    return;
} //}

//}


/** proxy a single socks5 connection */
//                class ClientConnection                      //{
ClientConnection::ClientConnection(Server* kserver, uv_loop_t* loop, 
                                   ConnectionProxy* mproxy,
                                   const std::string& addr, uint16_t port, Socks5Auth* socks5):
    mp_kserver(kserver), mp_loop(loop), mp_proxy(mproxy), m_server(addr), m_port(port), m_socks5(socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    this->m_state = __State::INITIAL;
    this->m_in_buffer = 0;
    this->m_out_buffer = 0;

    this->mp_tcp_client = nullptr;
    this->m_client_start_read = false;

    this->m_id = this->mp_proxy->requireAnId(this);
    std::cout << "get new id: " << (int)this->m_id << std::endl;
    assert(this->m_id < SINGLE_TSL_MAX_CONNECTION);
} //}

void ClientConnection::__start_relay() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_client_start_read == false);
    uv_read_start((uv_stream_t*)this->mp_tcp_client, malloc_cb, ClientConnection::client_read_cb);
    this->m_client_start_read = true;
} //}
// static
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

    should_run = should_run && (!_data->exited);
    if(should_run) _this->m_callbacks.erase(_this->m_callbacks.find(_data));
    delete _data;
    if(!should_run) return;

    _this->m_out_buffer -= buf_size;

    if(status < 0) {
        _this->close(true);
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
    this->m_callbacks.insert(x);

    uv_buf_t* uv_buf = new uv_buf_t();
    uv_buf->base = buf.__base();
    uv_buf->len  = buf.size();

    uv_write_t* req = new uv_write_t();
    auto ptr = new UVC::ClientConnection$write_to_client_callback$uv_write(this->mp_kserver, x, new ROBuf(buf), uv_buf);
    this->mp_kserver->callback_insert(ptr);
    uv_req_set_data((uv_req_t*)req, ptr);

    this->m_in_buffer += buf.size();

    uv_write(req, (uv_stream_t*)this->mp_tcp_client, uv_buf, 1, ClientConnection::write_to_client_callback);
} //}
// static
void ClientConnection::write_to_client_callback(uv_write_t* req, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::ClientConnection$write_to_client_callback$uv_write* m = 
        dynamic_cast<decltype(m)>(static_cast<EventEmitter*>(uv_req_get_data((uv_req_t*)req)));
    ROBuf* rbuf = m->_rbuf;
    uv_buf_t* ubuf = m->_ubuf;
    __proxyWriteInfo* info = m->_info;
    ClientConnection* _this = info->_this;
    bool should_run = m->should_run;
    size_t nwrite = ubuf->len;
    delete m;
    delete ubuf;
    delete rbuf;

    should_run = should_run && !info->exited;
    delete info;
    if(should_run) _this->m_callbacks.erase(_this->m_callbacks.find(info));

    if(!should_run) return;

    _this->m_in_buffer -= nwrite;
    // TODO traffic control
} //}

void ClientConnection::accept() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_socks5);
    assert(this->m_state == INITIAL);
    this->m_state = CONNECTING;
    this->m_socks5->send_reply(SOCKS5_REPLY_SUCCEEDED);
    this->m_socks5 = nullptr;
} //}
void ClientConnection::reject() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_socks5);
    this->m_socks5->send_reply(SOCKS5_REPLY_SERVER_FAILURE);
    this->m_socks5 = nullptr;
    this->close(true);
} //}

void ClientConnection::run(uv_tcp_t* client_tcp) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(client_tcp);
    assert(this->mp_tcp_client == nullptr);
    assert(this->m_state == CONNECTING);
    this->m_state = RUNNING;

    this->mp_tcp_client = client_tcp;
    uv_handle_set_data((uv_handle_t*)this->mp_tcp_client, this);
    this->__start_relay();
} //}
void ClientConnection::close(bool send_close) //{
{
    __logger->debug("call %s", FUNCNAME);
    auto prev_stat = this->m_state;
    this->m_state = __State::ERROR;
    for(auto& x: this->m_callbacks)
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

    this->mp_proxy->remove_connection(this->m_id, this, prev_stat == __State::RUNNING);
} //}

void ClientConnection::connect(Socks5Auth* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    if(this->mp_proxy->IsConnected())
        return this->__connect(socks5);

    this->mp_proxy->connect(ClientConnection::connect_callback, new std::tuple<ClientConnection*, Socks5Auth*>(this, socks5));
} //}
// static
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


/** multiplex a tls connection */
//                class ConnectionProxy                      //{
ConnectionProxy::ConnectionProxy(uv_loop_t* loop, Server* server, SingleServerInfo* server_info) //{
{
    __logger->debug("call %s", FUNCNAME);
    this->mp_loop = loop;
    this->mp_server = server;
    this->mp_server_info = server_info;

    this->m_out_buffer = 0;
    this->m_remain_raw = ROBuf();

    this->m_state = __State::STATE_INITIAL;

    this->mp_connection = nullptr;
    this->m_connection_read = false;

    this->m_connect_cb = nullptr;
    this->m_connect_cb_data = nullptr;
} //}

uint8_t ConnectionProxy::get_id() //{
{
    __logger->debug("call %s", FUNCNAME);
    for(uint8_t i=0; i<SINGLE_TSL_MAX_CONNECTION; i++) {
        if(this->m_map.find(i) == this->m_map.end())
            return i;
    }
    return SINGLE_TSL_MAX_CONNECTION;
} //}

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
        this->mp_server->callback_insert(ptr);

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
        this->mp_server->callback_insert(ptr);

        uv_getaddrinfo(this->mp_loop, p_req, 
                       ConnectionProxy::connect_remote_getaddrinfo_cb, 
                       this->mp_server_info->addr().c_str(), "80", &hints);
    }
} //}

// static
void ConnectionProxy::connect_remote_getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) //{
{
    __logger->debug("call %s", FUNCNAME);
    struct addrinfo *a;
    struct sockaddr_in* m;

    UVC::ConnectionProxy$connect_to_remote_server$uv_getaddrinfo* msg =
        dynamic_cast<decltype(msg)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    msg->_server->callback_remove(msg);
    bool clean = msg->_clean;
    ConnectionProxy* _this = msg->_this;
    bool should_run = msg->should_run;

    if(clean) delete req;
    delete msg;

    if(!should_run) {
        /* if(clean) */ uv_freeaddrinfo(res);
        _this->m_connect_cb(false, -1, _this->m_connect_cb_data);
        _this->m_connect_cb = nullptr;
        _this->m_connect_cb_data = nullptr;
        return;
    }

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
        logger->warn("%s: query dns doesn't get an ipv4 address", FUNCNAME);
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

void ConnectionProxy::connect_to_with_sockaddr(sockaddr* sock) //{
{
    __logger->debug("call %s", FUNCNAME);
    uv_connect_t* req = new uv_connect_t();
    auto ptr = new UVC::ConnectionProxy$connect_to_with_sockaddr$uv_tcp_connect(this->mp_server, this);
    uv_req_set_data((uv_req_t*)req, ptr);
    this->mp_server->callback_insert(ptr);

    assert(this->m_state == __State::STATE_GETDNS);
    this->m_state = __State::STATE_CONNECTING;

    uv_tcp_connect(req, this->mp_connection, sock, ConnectionProxy::connect_remote_tcp_connect_cb);
} //}

// static
void ConnectionProxy::connect_remote_tcp_connect_cb(uv_connect_t* req, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::ConnectionProxy$connect_to_with_sockaddr$uv_tcp_connect* ptr =
        dynamic_cast<decltype(ptr)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    assert(ptr);
    Server* server = ptr->_server;
    ConnectionProxy* _this = ptr->_this;
    bool should_run = ptr->should_run;
    delete req;
    delete ptr;

    server->callback_remove(ptr);
    if(!should_run) {
        _this->m_connect_cb(false, -1, _this->m_connect_cb_data);
        _this->m_connect_cb = nullptr;
        _this->m_connect_cb_data = nullptr;
        return;
    }

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

void ConnectionProxy::tsl_handshake() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_state == __State::STATE_CONNECTING);
    this->m_state = __State::STATE_TSL;
    this->client_authenticate();
} //}

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

// static
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

// static
void ConnectionProxy::uv_stream_read_after_send_auth_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    ConnectionProxy* _this = 
        dynamic_cast<decltype(_this)>(static_cast<EventEmitter*>(uv_handle_get_data((uv_handle_t*)stream)));
    assert(_this);

    if(nread <= 0) {
        _this->close(CLOSE_READ_ERROR);
        free(buf->base);
        _this->m_connect_cb(true, -1, _this->m_connect_cb_data);
        _this->m_connect_cb = nullptr;
        _this->m_connect_cb_data = nullptr;
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

void ConnectionProxy::dispatch_data_encrypted(ROBuf buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    this->dispatch_data(buf);
} //}

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
                if(this->m_map.find(id) == this->m_map.end()) {
                    __logger->warn("ConnectionProxy recieves a packet to ClientConnection which doesn't exists. REG");
                    this->close_connection(id, nullptr, nullptr);
                } else {
                    cc->PushData(frame);
                }
                break;
            case PACKET_OP_CLOSE:
                if(this->m_map.find(id) == this->m_map.end()) {
                    __logger->warn("ConnectionProxy recieves a packet to ClientConnection which doesn't exists. CLOSE");
                } else {
                    cc->close(false);
                }
                break;
            case PACKET_OP_CONNECT:
                if(this->m_wait_new_connection.find(id) == this->m_wait_new_connection.end()) {
                    __logger->warn("ConnectionProxy recieves a packet to ClientConnection which doesn't exists. CONNECT");
                    this->close_connection(id, nullptr, nullptr);
                } else {
                    assert(this->m_map.find(id) != this->m_map.end());
                    this->m_wait_new_connection.erase(this->m_wait_new_connection.find(id));
                    this->m_map[id]->accept();
                }
                break;
            case PACKET_OP_REJECT:
                if(this->m_wait_new_connection.find(id) == this->m_wait_new_connection.end()) {
                    __logger->warn("ConnectionProxy recieves a packet to ClientConnection which doesn't exists. REJECT");
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
    this->mp_server->callback_insert(ptr);

    this->m_out_buffer += buf.size();
    return uv_write(req, (uv_stream_t*)this->mp_connection, uv_buf, 1, ConnectionProxy::_write_callback);
} //}

// static
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
    bool should_run = msg->should_run;
    _this->mp_server->callback_remove(msg);

    if(should_run) _this->m_out_buffer -= mem_holder->size();

    delete msg;
    delete uv_buf;

    if(cb != nullptr)
        cb(should_run, status, mem_holder, data);
    else
        delete mem_holder;

    if(!should_run) return;

    if(status < 0) {
        _this->close(CLOSE_WRITE_ERROR);
        return;
    }
} //}

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
    this->mp_server->callback_insert(ptr);
    uv_timer_start(timer, ConnectionProxy::new_connection_timer_callback, NEW_CONNECTION_TIMEOUT, 0);

    return ret;
} //}

// static
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
        cb(should_run, status, buf, data);
    } else {
        delete buf;
    }
} //}
void ConnectionProxy::new_connection_timer_callback(uv_timer_t* timer) //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::ConnectionProxy$new_connection$uv_timer_start* msg = 
        dynamic_cast<decltype(msg)>(static_cast<UVC::UVCBaseClient*>(uv_handle_get_data((uv_handle_t*)timer)));
    assert(msg);
    msg->_server->callback_remove(msg);
    ConnectionProxy* _this = msg->_this;
    new_connection_wrapper_data* _data = static_cast<decltype(_data)>(msg->_data);
    bool should_run = msg->should_run;
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
        if(_this->m_wait_new_connection.find(id) != _this->m_wait_new_connection.end()) {
            _this->m_wait_new_connection.erase(_this->m_wait_new_connection.find(id));
        }
    }
} //}

int ConnectionProxy::close_connection(uint8_t id, WriteCallback cb, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    auto x = encode_packet(PACKET_OP_CLOSE, id, ROBuf((char*)"close", 5));
    return this->_write(x, cb, data);
} //}

void ConnectionProxy::remove_connection(uint8_t id, ClientConnection* obj, bool remove) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_map.find(id) != this->m_map.end());
    this->m_map.erase(this->m_map.find(id));
    if(remove) delete obj;
} //}

uint8_t ConnectionProxy::requireAnId(ClientConnection* cc) //{
{
    __logger->debug("call %s", FUNCNAME);
    uint8_t id = this->get_id();
    assert(id < (1 << 6));
    this->m_map[id] = cc;
    return id;
} //}

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
} //}

ConnectionProxy::~ConnectionProxy() //{
{
    __logger->debug("call %s", FUNCNAME);
} //}

//}


/** directly proxy a connection through this client */
//                class RelayConnection                       //{
RelayConnection::RelayConnection(Server* kserver, uv_loop_t* loop, uv_tcp_t* tcp_client, const std::string& server, uint16_t port) //{
{
    __logger->debug("call %s: relay connection to %s:%d", FUNCNAME, server.c_str(), k_ntohs(port));
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
    __logger->debug("call %s", FUNCNAME);
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
    __logger->debug("call %s", FUNCNAME);
    this->mp_tcp_client = client_tcp;
    uv_handle_set_data((uv_handle_t*)this->mp_tcp_client, this);
    if(this->mp_tcp_server != nullptr)
        this->__start_relay();
    else
        this->close();
} //}

void RelayConnection::close() //{
{
    __logger->debug("call %s = (this=0x%lx)", FUNCNAME, (long)this);
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
            uv_close((uv_handle_t*)this->mp_tcp_server, delete_closed_handle<decltype(this->mp_tcp_server)>);
            this->mp_tcp_server = nullptr;
        }
        uv_close((uv_handle_t*)this->mp_tcp_client, delete_closed_handle<decltype(this->mp_tcp_client)>);
        this->mp_tcp_client = nullptr;
        return this->m_kserver->close_relay(this);
    }
} //}

void RelayConnection::__connect_to(const sockaddr* addr, Socks5Auth* socks5) //{
{
    __logger->debug("call %s = (this=0x%lx)", FUNCNAME, (long)this);

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
    __logger->debug("call %s", FUNCNAME);
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
        /* if(clean) */ uv_freeaddrinfo(res);
        return;
    }

    if(status < 0) {
        __logger->warn("%s: dns query fail", FUNCNAME);
        // TODO send a close packet
        if(clean) uv_freeaddrinfo(res);
        return socks5->send_reply(SOCKS5_REPLY_HOST_UNREACHABLE);
    }
    for(a = res; a != nullptr; a = a->ai_next) {
        if(sizeof(struct sockaddr_in) != a->ai_addrlen) {
            __logger->debug("%s: query dns get an address that isn't ipv4 address", FUNCNAME);
            continue;
        } else break;
    }
    if(a == nullptr) {
        logger->warn("%s: query dns doesn't get an ipv4 address", FUNCNAME);
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
    __logger->debug("call %s", FUNCNAME);
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
            __logger->debug("%s: fail", FUNCNAME);
            uv_close((uv_handle_t*) _this->mp_tcp_server, delete_closed_handle<decltype(_this->mp_tcp_server)>);
            _this->mp_tcp_server = nullptr;
            return socks5->send_reply(SOCKS5_REPLY_CONNECTION_REFUSED);
        } else {
            return socks5->send_reply(SOCKS5_REPLY_SUCCEEDED);
        }
    }
} //}

void RelayConnection::__start_relay() //{
{
    __logger->debug("call %s", FUNCNAME);
    this->__relay_client_to_server();
    this->__relay_server_to_client();
} //}

void RelayConnection::__relay_client_to_server() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_client_start_read == false);
    uv_read_start((uv_stream_t*)this->mp_tcp_client, 
            malloc_cb, 
            RelayConnection::client_read_cb);
    this->m_client_start_read = true;
} //}
void RelayConnection::__relay_server_to_client() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->m_server_start_read == false);
    uv_read_start((uv_stream_t*)this->mp_tcp_server, 
            malloc_cb, 
            RelayConnection::server_read_cb);
    this->m_server_start_read = true;
} //}

void RelayConnection::client_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    if(nread == 0) {
        free(buf->base);
        return;
    }
    RelayConnection* _this = (RelayConnection*)uv_handle_get_data((uv_handle_t*)stream);
    if(nread < 0) {
        _this->close();
        free(buf->base);
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
    __logger->debug("call %s", FUNCNAME);
    if(nread == 0) {
        free(buf->base);
        return;
    }
    RelayConnection* _this = (RelayConnection*)uv_handle_get_data((uv_handle_t*)stream);
    if(nread < 0) {
        _this->close();
        free(buf->base);
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
    __logger->debug("call %s", FUNCNAME);
    UVC::RelayConnection$xxxx_read_cb$uv_write* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    x->_server->callback_remove(x);
    RelayConnection* _this = x->_this;
    const uv_buf_t* buf = x->uv_buf;
    bool should_run = x->should_run;
    delete x;
    delete req;

    _this->m_out_buffer -= buf->len;
    free(buf->base);
    delete buf;

    if(!should_run) return _this->close();

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
    __logger->debug("call %s", FUNCNAME);
    UVC::RelayConnection$xxxx_read_cb$uv_write* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    x->_server->callback_remove(x);
    RelayConnection* _this = x->_this;
    const uv_buf_t* buf = x->uv_buf;
    bool should_run = x->should_run;
    delete x;
    delete req;

    _this->m_in_buffer -= buf->len;
    free(buf->base);
    delete buf;

    if(!should_run) return _this->close();

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
    __logger->debug("call %s", FUNCNAME);
    assert(this->mp_tcp_client == nullptr);
    if(this->mp_tcp_server != nullptr)
        uv_close((uv_handle_t*)this->mp_tcp_server, delete_closed_handle<decltype(this->mp_tcp_server)>);
} //}
//}

}

