#include "../include/kclient.h"
#include "../include/config.h"
#include "../include/socks5.h"
#include "../include/uv_callback_data.h"

#include <tuple>
#include <vector>
#include <ostream>

#define NEW_CONNECTION_TIMEOUT (3 * 2000)

namespace KProxyClient {

/** malloc callback for uv_read */
static void malloc_cb(uv_handle_t*, size_t suggested_size, uv_buf_t* buf) //{
{
    buf->base = (char*)malloc(suggested_size);
    buf->len  = suggested_size;
} //}
/** callback for uv_close(uv_handle_t*) */
template<typename T>
static void delete_closed_handle(uv_handle_t* h) {delete static_cast<T>(static_cast<void*>(h));}


/** calss Socks5Auth 
 * hold a session to complete socks5 method select, user authentication, request */
//                  class Socks5Auth                     //{
/** constructor of Socks5Auth */
Socks5Auth::Socks5Auth(Server* server, uv_tcp_t* client, ClientConfig* config) //{
{
    __logger->debug("call %s: new socks5 authentication session", FUNCNAME);
    this->mp_server = server;
    this->mp_server->register_object(this);

    this->mp_loop = uv_handle_get_loop((uv_handle_t*)client);
    this->m_state = SOCKS5_INIT;
    this->mp_config = config;
    this->mp_client = client;

    this->m_remain = ROBuf();

    this->m_servername = "";
    this->m_port = 80;

    this->m_client_read_start = true;
    
    this->setup_uv_tcp_data();
    uv_read_start((uv_stream_t*)this->mp_client, malloc_cb, Socks5Auth::read_callback);
} //}

void Socks5Auth::setup_uv_tcp_data() //{
{
    __logger->debug("call %s", FUNCNAME);
    auto ptr = new UVC::Socks5Auth$uv_read_start(this->mp_server, this);
    uv_handle_set_data((uv_handle_t*)this->mp_client, ptr);
    this->mp_server->callback_insert(ptr, this);
} //}
void Socks5Auth::clean_uv_tcp_data() //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::Socks5Auth$uv_read_start* _data =
        dynamic_cast<decltype(_data)>(static_cast<UVC::UVCBaseClient*>(uv_handle_get_data((uv_handle_t*)this->mp_client)));
    auto pp = _data->_server->callback_remove(_data); // TODO
    assert(pp == this);
    delete _data;
    uv_handle_set_data((uv_handle_t*)this->mp_client, nullptr);
} //}

/** recieve the socks5 request, forward this message to Server try to connect the request service */
void Socks5Auth::try_to_build_connection() //{
{
    __logger->debug("call %s: try to build a connection to server", FUNCNAME);
    assert(this->m_state == SOCKS5_FINISH);
    if(m_client_read_start) {
        uv_read_stop((uv_stream_t*)this->mp_client);
        this->m_client_read_start = false;
    }
    this->mp_server->socks5BuildConnection(this, this->m_servername, this->m_port);
} //}
/** transfer tcp connection to Server */
void Socks5Auth::return_to_server() //{ 
{
    __logger->debug("call %s", FUNCNAME);
    if(m_client_read_start) {
        uv_read_stop((uv_stream_t*)this->mp_client);
        this->m_client_read_start = false;
    }
    this->clean_uv_tcp_data();
    this->mp_server->callback_remove_owner(this);
    this->mp_server->socks5Transfer(this, this->mp_client);
} //}
/** something wrong has happend inform Server to deallocate memory */
void Socks5Auth::close_this_with_error() //{
{
    __logger->debug("call %s", FUNCNAME);
    this->m_state = SOCKS5_ERROR;
    if(m_client_read_start) {
        uv_read_stop((uv_stream_t*)this->mp_client);
        this->m_client_read_start = false;
    }
    this->clean_uv_tcp_data();
    this->mp_server->callback_remove_owner(this);
    this->mp_server->socks5Reject(this, this->mp_client);
} //}

/** socks5 request read callback, which will dispatch data to Socks5Auth::dispatch_data(ROBuf buf) */
void Socks5Auth::read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    __logger->debug("call %s = (0x%lx, %d, 0x%lx)", FUNCNAME, (long)stream, (int)nread, (long)buf);
    UVC::Socks5Auth$uv_read_start* _data =
        dynamic_cast<decltype(_data)>(static_cast<UVC::UVCBaseClient*>(uv_handle_get_data((uv_handle_t*)stream)));
    assert(_data);
    if(nread <= 0) {
        free(buf->base);
        _data->_this->m_state = SOCKS5_ERROR;
        _data->_this->return_to_server();
        return;
    }
    ROBuf bufx = ROBuf(buf->base, nread, 0, free);
    _data->_this->dispatch_data(bufx);
} //}
/** dispatch data base on current state */
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
                this->close_this_with_error();
                break;
            }
            if(finished) {
                if(msg.m_version  != 0x5 ||
                   msg.m_command != SOCKS5_CMD_CONNECT ||
                   (msg.m_addr_type != SOCKS5_ADDR_IPV4 && msg.m_addr_type != SOCKS5_ADDR_DOMAIN)) {
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

/** send message to socks5 client */
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
    this->mp_server->callback_insert(ptr, this);
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
    this->mp_server->callback_insert(ptr, this);
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
    this->mp_server->callback_insert(ptr, this);
    uv_write(req, (uv_stream_t*)this->mp_client, buf, 1, Socks5Auth::write_callback_reply);
} //}

/** corresponding callback for uv_write() in above three function */
void Socks5Auth::write_callback_hello(uv_write_t* req, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::Socks5Auth$__send_selection_method$uv_write* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    assert(x);
    auto pp = x->_server->callback_remove(x);
    Socks5Auth* _this = x->_this;
    uv_buf_t* buf = x->uv_buf;
    bool should_run = (pp != nullptr);
    delete x;
    delete (__server_selection_msg*)buf->base;
    delete buf;
    delete req;
    if(should_run) assert(pp == _this);
    if(status != 0 && should_run) _this->close_this_with_error();
} //}
void Socks5Auth::write_callback_id(uv_write_t* req, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::Socks5Auth$__send_auth_status$uv_write* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    assert(x);
    auto pp = x->_server->callback_remove(x);
    Socks5Auth* _this = x->_this;
    uv_buf_t* buf = x->uv_buf;
    bool should_run = (pp != nullptr);
    if(should_run) assert(pp == _this);
    delete x;
    delete (__socks5_user_authentication_reply*)buf->base;
    delete buf;
    delete req;
    if(status != 0 && should_run) _this->close_this_with_error();
} //}
void Socks5Auth::write_callback_reply(uv_write_t* req, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::Socks5Auth$__send_reply$uv_write* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    assert(x);
    auto pp = x->_server->callback_remove(x);
    Socks5Auth* _this = x->_this;
    uv_buf_t* buf = x->uv_buf;
    uint8_t reply = x->reply;
    bool should_run = (pp != nullptr);
    delete x;
    free(buf->base);
    delete buf;
    delete req;
    if(should_run) {
        assert(pp == _this);
        if(status != 0 || _this->m_remain.size() != 0 || reply != SOCKS5_REPLY_SUCCEEDED)
            _this->close_this_with_error();
        else 
            _this->return_to_server(); 
    }
} //}

/** wrapper of @close_this_with_error() */
void Socks5Auth::close() //{
{
    __logger->debug("call %s", FUNCNAME);
    this->close_this_with_error();
} //}
//}


/** class Server
 * listen to an tcp address to provide service, and manage resources */
//                class Server                                //{
/** constructor of Server */
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
        dynamic_cast<UVC::KProxyClient$Server$uv_listen*>(
                static_cast<UVC::UVCBaseClient*>(uv_handle_get_data((uv_handle_t*)this->mp_uv_tcp)));
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

    uv_tcp_t* client = new uv_tcp_t(); // FIXME memory leak
    uv_tcp_init(x->_this->mp_uv_loop, client);

    if(uv_accept(stream, (uv_stream_t*)client) < 0) {
        __logger->warn("accept new connection error");
        uv_close((uv_handle_t*)client, delete_closed_handle<decltype(client)>);
        return;
    }
    Socks5Auth* auth = new Socks5Auth(_this, client, _this->m_config); // FIXME memory leak
    _this->m_auths[auth] = std::make_tuple(true, nullptr); 
} //}

/** functions interact with Socks5Auth object provide functions likes 
 *    connecting to server
 *    close Socks5Auth object 
 *    transfer tcp connection of completed Socks5Auth to RelayConnection or Proxy */
void Server::socks5BuildConnection(Socks5Auth* socks5, const std::string& addr, uint16_t port) //{ 
{
    this->dispatch_base_on_addr(addr, port, socks5);
    return;
} //}
void Server::socks5Reject(Socks5Auth* socks5, uv_tcp_t* client_tcp) //{
{
    delete socks5;
    uv_close((uv_handle_t*)client_tcp, delete_closed_handle<decltype(client_tcp)>);
    if(this->m_auths.find(socks5) == this->m_auths.end()) return;
    auto mm = this->m_auths[socks5];

    if(std::get<1>(mm) != nullptr) {
        ClientConnection* cc = dynamic_cast<ClientConnection*>(std::get<1>(mm));
        RelayConnection*  cr = dynamic_cast<RelayConnection*>(std::get<1>(mm));
        if(std::get<0>(mm)) { // bypass
            assert(cr || cc == nullptr);
            cr->SetSocks5NULL();
            cr->close();
        } else { // proxy
            assert(cc || cr == nullptr);
            cc->SetSocks5NULL();
            cc->close(false);
        }
        this->try_close();
    }
    this->m_auths.erase(this->m_auths.find(socks5));
    return;
} //}
void Server::socks5Transfer(Socks5Auth* socks5, uv_tcp_t* client_tcp) //{
{
    delete socks5;
    if(this->m_auths.find(socks5) == this->m_auths.end())
        uv_close((uv_handle_t*)client_tcp, delete_closed_handle<decltype(client_tcp)>);
    else
        this->redispatch(client_tcp, socks5);
    return;
} //}
void Server::socks5Remove(Socks5Auth* socks5) //{
{
    assert(this->m_auths.find(socks5) != this->m_auths.end());
    this->m_auths.erase(this->m_auths.find(socks5));
} //}

int Server::listen() //{ 
{
    __logger->debug("call %s", FUNCNAME);
    this->m_config->loadFromFile(Server::on_config_load, this);
    return 0;
} //}
void Server::on_config_load(int error, void* data) //{
{
    __logger->debug("call %s", FUNCNAME);
    Server* _this = (Server*) data;
    if(error > 0) {
        __logger->error("load config file fail");
        exit(1);
    }
    _this->bind_addr = _this->m_config->BindAddr();
    _this->bind_port = _this->m_config->BindPort();
    _this->__listen();
} //}
int Server::__listen() //{ 
{
    __logger->debug("call %s", FUNCNAME);
    sockaddr_in addr;

    uint32_t network_order_addr = this->bind_addr;

    uv_ip4_addr(ip4_to_str(network_order_addr), this->bind_port, &addr);
    int s = uv_tcp_bind(this->mp_uv_tcp, (sockaddr*)&addr, 0);
    if(s != 0) {
        __logger->error("bind error %s:%d", ip4_to_str(network_order_addr), this->bind_port);
        return s;
    }
    s = uv_listen((uv_stream_t*)this->mp_uv_tcp, MAX_LISTEN, Server::on_connection);
    if(s != 0) {
        __logger->error("listen error %s:%d", ip4_to_str(network_order_addr), this->bind_port);
        return s;
    }
    this->run___ = true;
    __logger->debug("listen at %s:%d", ip4_to_str(network_order_addr), this->bind_port);
    return 0;
} //}

/** dispatch socks5 request from Socks5Auth */
void Server::dispatch_base_on_addr(const std::string& addr, uint16_t port, Socks5Auth* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    this->dispatch_bypass(addr, port, socks5);
//    this->dispatch_proxy(addr, port, socks5);
} //}
void Server::dispatch_bypass(const std::string& addr, uint16_t port, Socks5Auth* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    RelayConnection* relay = new RelayConnection(this, this->mp_uv_loop, socks5, nullptr, addr, port);
    this->m_relay.insert(relay);
    this->m_auths[socks5] = std::make_tuple(true, relay);
    relay->connect();
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

/** transfer tcp connection from Socks5Auth to RelayConnection or Proxy */
void Server::redispatch(uv_tcp_t* client_tcp, Socks5Auth* socks5) //{
{
    __logger->debug("call %s", FUNCNAME);
    auto ff = this->m_auths.find(socks5);
    assert(ff != this->m_auths.end());
    ClientConnection* cc = dynamic_cast<ClientConnection*>(std::get<1>(ff->second));
    RelayConnection*  cr = dynamic_cast<RelayConnection*> (std::get<1>(ff->second));
    if(std::get<0>(ff->second)) {
        assert(cr);
        cr->run(client_tcp);
    } else {
        assert(cc);
        cc->run(client_tcp);
    }
    this->m_auths.erase(ff);
} //}

/** select a remote server base on some strategies */
SingleServerInfo* Server::select_remote_serever() //{
{
    __logger->debug("call %s", FUNCNAME);
    for(auto& x: this->m_config->Servers())
        return &x;
    return nullptr;
} //}

/** deallocate RelayConnection and ConnectionProxy */
void Server::remove_relay(RelayConnection* relay) //{
{
    __logger->debug("call %s, connections: %d", FUNCNAME, this->m_auths.size() + this->m_relay.size());
    assert(this->m_relay.find(relay) != this->m_relay.end());
    this->m_relay.erase(this->m_relay.find(relay));
    delete relay;
    this->try_close();
} //}
void Server::remove_proxy(ConnectionProxy* proxy) //{
{
    __logger->debug("call %s, connections: %d", FUNCNAME, this->m_auths.size() + this->m_relay.size());
    assert(this->m_proxy.find(proxy) != this->m_proxy.end());
    this->m_proxy.erase(this->m_proxy.find(proxy));
    delete proxy;
    this->try_close();
} //}

/** when every object has deconstructed and callback has finished, change state to exit */
void Server::try_close() //{
{
    __logger->debug("call %s", FUNCNAME);
    if(this->exit__ == false) return;

    if(this->m_auths.size() == 0 && 
       this->m_relay.size() == 0 && 
       this->m_proxy.size() == 0 && 
       this->CallbackLength() == 0) 
        this->run___ = false;
} //}
/** deallocate every which had allocated by this object */
void Server::close() //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->exit__ == false);
    this->exit__ = true;
    uv_close((uv_handle_t*)this->mp_uv_tcp, nullptr); // block api

    std::cout << "relay: " << this->m_relay.size() << std::endl;
    auto copy_relay = this->m_relay;
    for(auto& relay: copy_relay)
        relay->close();

    std::cout << "proxy: " << this->m_proxy.size() << std::endl;
    auto copy_proxy = this->m_proxy;
    for(auto& proxy: copy_proxy)
        proxy->close(ConnectionProxy::CLOSE_REQUIRED);

    std::cout << "auths: " << this->m_auths.size() << std::endl;
    auto copy_auth = this->m_auths;
    for(auto& auth: copy_auth)
        auth.first->close();

    std::cout << "waiting callbacks: " << this->CallbackLength() << std::endl;

    this->try_close();
    return;
} //}
//}


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

    assert(this->m_state == __State::STATE_GETDNS);
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


/** class RelayConnection
 * directly proxy a connection through this client */
//                class RelayConnection                       //{
/** constructor of RelayConnection */
RelayConnection::RelayConnection(Server* kserver, uv_loop_t* loop, 
                                 Socks5Auth* socks5, uv_tcp_t* tcp_client, 
                                 const std::string& server, uint16_t port) //{
{
    __logger->debug("call %s: relay connection to %s:%d", FUNCNAME, server.c_str(), port);
    assert(tcp_client == nullptr);
    this->m_kserver = kserver;
    this->m_kserver->register_object(this);

    this->mp_loop = loop;

    this->mp_tcp_client = tcp_client;
    this->mp_socks5 = socks5;

    this->m_in_buffer = 0;
    this->m_out_buffer = 0;

    this->mp_tcp_server = nullptr;

    this->m_server = server;
    this->m_port = port;

    this->m_exited = false;

    this->m_client_start_read = false;
    this->m_server_start_read = false;
}
//}

/** connect to tcp address that specified by socks5 request */
void RelayConnection::connect() //{
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
        auto ptr = new UVC::RelayConnection$connect$uv_getaddrinfo(this->m_kserver, false, this);
        uv_req_set_data((uv_req_t*)&req, ptr);
        this->m_kserver->callback_insert(ptr, this);
        RelayConnection::getaddrinfo_cb(&req, 0, &info);
    } else {
        struct addrinfo hints;
        hints.ai_family = AF_INET;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = 0;

        uv_getaddrinfo_t* p_req = new uv_getaddrinfo_t();
        auto ptr = new UVC::RelayConnection$connect$uv_getaddrinfo(this->m_kserver, true, this);
        uv_req_set_data((uv_req_t*)p_req, ptr);
        this->m_kserver->callback_insert(ptr, this);

        uv_getaddrinfo(this->mp_loop, p_req, RelayConnection::getaddrinfo_cb, this->m_server.c_str(), "80", &hints);
    }
} //}

/** [static] callback for uv_getaddrinfo() in @RelayConnection::connect() */
void RelayConnection::getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) //{
{
    __logger->debug("call %s", FUNCNAME);
    struct addrinfo *a;
    struct sockaddr_in* m;

    UVC::RelayConnection$connect$uv_getaddrinfo* msg =
        dynamic_cast<decltype(msg)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    auto pp = msg->_server->callback_remove(msg);
    bool clean = msg->is_uv;
    RelayConnection* _this = msg->_this;
    bool should_run = (pp != nullptr);
    if(clean) delete req;
    delete msg;

    if(!should_run) {
        /* if(clean) */ uv_freeaddrinfo(res);
        return;
    }

    assert(pp == _this);

    if(status < 0) {
        __logger->warn("%s: dns query fail", FUNCNAME);
        if(clean) uv_freeaddrinfo(res);
        return _this->mp_socks5->send_reply(SOCKS5_REPLY_HOST_UNREACHABLE);
    }
    for(a = res; a != nullptr; a = a->ai_next) {
        if(sizeof(struct sockaddr_in) != a->ai_addrlen) {
            __logger->debug("%s: query dns get an address that isn't ipv4 address", FUNCNAME);
            continue;
        } else break;
    }
    if(a == nullptr) {
        __logger->warn("%s: query dns doesn't get an ipv4 address", FUNCNAME);
        if(clean) uv_freeaddrinfo(res);
        return _this->mp_socks5->send_reply(SOCKS5_REPLY_ADDRESSS_TYPE_NOT_SUPPORTED);
    }
    m = (struct sockaddr_in*)a->ai_addr; // FIXME
    m->sin_port = k_htons(_this->m_port);
    _this->__connect_to((sockaddr*)m);
    if(clean) uv_freeaddrinfo(res);
} //}

/** transfer tcp connection from Socks5Auth object to this object */
void RelayConnection::run(uv_tcp_t* client_tcp) //{
{
    __logger->debug("call %s", FUNCNAME);
    assert(this->mp_socks5 != nullptr);
    this->mp_socks5 = nullptr;
    this->mp_tcp_client = client_tcp;
    uv_handle_set_data((uv_handle_t*)this->mp_tcp_client, this);
    assert(this->mp_tcp_server != nullptr);
    this->__start_relay();
} //}

/** close this object */
void RelayConnection::close() //{
{
    __logger->debug("call %s = (this=0x%lx)", FUNCNAME, (long)this);
    assert(this->m_exited == false);
    this->m_exited = true;

    if(this->mp_socks5 != nullptr) {
        this->m_kserver->socks5Remove(this->mp_socks5);
        this->mp_socks5->close();
        this->mp_socks5 = nullptr;
    }

    if(this->m_server_start_read) {
        uv_read_stop((uv_stream_t*)this->mp_tcp_server);
        this->m_server_start_read = false;
    }
    if(this->m_client_start_read) {
        uv_read_stop((uv_stream_t*)this->mp_tcp_client);
        this->m_client_start_read = false;
    }

    if(this->mp_tcp_server != nullptr) {
        uv_close((uv_handle_t*)this->mp_tcp_server, delete_closed_handle<decltype(this->mp_tcp_server)>);
        this->mp_tcp_server = nullptr;
    }
    if(this->mp_tcp_client != nullptr) {
        uv_close((uv_handle_t*)this->mp_tcp_client, delete_closed_handle<decltype(this->mp_tcp_client)>);
        this->mp_tcp_client = nullptr;
    }

    this->m_kserver->callback_remove_owner(this);
    return this->m_kserver->remove_relay(this);
} //}

/** this function will call uv_tcp_connect() try to connect with #addr */
void RelayConnection::__connect_to(const sockaddr* addr) //{
{
    __logger->debug("call %s = (this=0x%lx)", FUNCNAME, (long)this);

    uv_connect_t* req = new uv_connect_t();
    auto ptr = new UVC::RelayConnection$__connect_to$uv_tcp_connect(this->m_kserver, this);
    uv_req_set_data((uv_req_t*)req, ptr);
    this->m_kserver->callback_insert(ptr, this);

    uv_tcp_t* tcp = new uv_tcp_t();
    uv_tcp_init(this->mp_loop, tcp);
    this->mp_tcp_server = tcp;
    uv_handle_set_data((uv_handle_t*)this->mp_tcp_server, this);

    // TODO set a timeout
    uv_tcp_connect(req, tcp, addr, RelayConnection::connect_server_cb);
} //}
/** [static] callback for uv_tcp_connect() in @RelayCOnnection::__connect_to() */
void RelayConnection::connect_server_cb(uv_connect_t* req, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::RelayConnection$__connect_to$uv_tcp_connect* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    auto pp = x->_server->callback_remove(x);
    RelayConnection* _this = x->_this;
    bool should_run = (pp != nullptr);
    delete x;
    delete req;

    if(!should_run) return;
    assert(pp == _this);

    if(status < 0) {
        __logger->debug("%s: fail", FUNCNAME);
        uv_close((uv_handle_t*) _this->mp_tcp_server, delete_closed_handle<decltype(_this->mp_tcp_server)>);
        _this->mp_tcp_server = nullptr;
        return _this->mp_socks5->send_reply(SOCKS5_REPLY_CONNECTION_REFUSED);
    } else {
        return _this->mp_socks5->send_reply(SOCKS5_REPLY_SUCCEEDED);
    }
} //}

/** start dual direction tcp relay */
void RelayConnection::__start_relay() //{
{
    __logger->debug("call %s", FUNCNAME);
    this->__relay_client_to_server();
    this->__relay_server_to_client();
} //}

/** As name suggested */
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

/** As name suggested */
void RelayConnection::client_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    __logger->debug("call %s", FUNCNAME);
    if(nread == 0) {
        free(buf->base);
        return;
    }
    RelayConnection* _this = static_cast<decltype(_this)>(uv_handle_get_data((uv_handle_t*)stream));
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
    _this->m_kserver->callback_insert(ptr, _this);
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
    RelayConnection* _this = static_cast<decltype(_this)>(uv_handle_get_data((uv_handle_t*)stream));
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
    _this->m_kserver->callback_insert(ptr, _this);
    _this->m_in_buffer += nread;
    uv_write(req, (uv_stream_t*)_this->mp_tcp_client, bufx, 1, RelayConnection::client_write_cb);

    if(_this->m_in_buffer > RELAY_MAX_BUFFER_SIZE) {
        uv_read_stop(stream);
        _this->m_server_start_read = false;
    }
} //}

/** As name suggested */
void RelayConnection::server_write_cb(uv_write_t* req, int status) //{
{
    __logger->debug("call %s", FUNCNAME);
    UVC::RelayConnection$xxxx_read_cb$uv_write* x = 
        dynamic_cast<decltype(x)>(static_cast<UVC::UVCBaseClient*>(uv_req_get_data((uv_req_t*)req)));
    auto pp = x->_server->callback_remove(x);
    RelayConnection* _this = x->_this;
    const uv_buf_t* buf = x->uv_buf;
    bool should_run = (pp != nullptr);
    delete x;
    delete req;

    free(buf->base);
    int buf_size = buf->len;
    delete buf;

    if(!should_run) return;
    assert(pp == _this);
    _this->m_out_buffer -= buf_size;

    if(status != 0) {
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
    auto pp = x->_server->callback_remove(x);
    RelayConnection* _this = x->_this;
    const uv_buf_t* buf = x->uv_buf;
    bool should_run = (pp != nullptr);
    delete x;
    delete req;

    free(buf->base);
    int buf_size = buf->len;
    delete buf;

    if(!should_run) return;
    assert(pp == _this);
    _this->m_in_buffer -= buf_size;

    if(status != 0) {
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

