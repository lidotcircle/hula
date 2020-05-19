#include "../include/kclient.h"
#include "../include/config.h"
#include "../include/socks5.h"

#include <tuple>
#include <vector>


namespace KProxyClient {


static void malloc_cb(uv_handle_t*, size_t suggested_size, uv_buf_t* buf) //{
{
    buf->base = (char*)malloc(suggested_size);
    buf->len  = suggested_size;
} //}
static void delete_closed_handle(uv_handle_t* h) {delete h;}

//                  class Socks5Auth                     //{
Socks5Auth::Socks5Auth(uv_tcp_t* client, ClientConfig* config, finish_cb cb, void* data) //{
{
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
    
    uv_handle_set_data((uv_handle_t*)this->mp_client, this);
    uv_read_start((uv_stream_t*)this->mp_client, malloc_cb, Socks5Auth::read_callback);
} //}

void Socks5Auth::return_to_server() //{ 
{
    int status = -1;
    if(this->m_state == SOCKS5_FINISH) status = 0;
    if(!m_client_read_start) {
        uv_read_stop((uv_stream_t*)this->mp_client);
        this->m_client_read_start = false;
    }
    this->m_cb(status, this, this->m_servername, this->m_port, this->mp_client, this->m_data);
} //}

void Socks5Auth::read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    Socks5Auth* _this = (Socks5Auth*)uv_handle_get_data((uv_handle_t*)stream);
    if(nread == 0) {
        // TODO
        return;
    }
    ROBuf bufx = ROBuf(buf->base, buf->len, 0, free);
    delete buf;
    _this->dispatch_data(bufx);
} //}

void Socks5Auth::dispatch_data(ROBuf buf) //{
{
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
                    return this->return_to_server();
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
        case SOCKS5_ID: {
            auto x = parse_username_authentication(this->m_remain, buf);
            bool finished;
            __socks5_username_password msg;
            ROBuf buf;
            std::tie(finished, msg, buf) = x;
            this->m_remain = buf;
            if(finished) {
                if(msg.m_version != 0x5) {
                    // TODO inform error
                    this->return_to_server();
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
                this->return_to_server();
                break;
            }
            if(finished) {
                if(msg.m_version  != 0x5 ||
                   msg.m_command != SOCKS5_CMD_CONNECT ||
                   (msg.m_addr_type != SOCKS5_ADDR_IPV4 && msg.m_addr_type != SOCKS5_ADDR_DOMAIN)) {
                    // TODO inform error
                    this->return_to_server();
                    break;
                }
                this->m_servername = msg.m_addr;
                this->m_port = msg.m_port;
                this->m_state = SOCKS5_FINISH;
                this->__send_reply(0x00); // TODO
            }
        }
        case SOCKS5_FINISH:
            assert(false && "bug");
            break;
    }
} //}

void Socks5Auth::__send_selection_method(socks5_authentication_method method) //{
{
    __server_selection_msg* msg = new __server_selection_msg();
    msg->m_version = 0x5;
    msg->m_method = method;
    uv_buf_t* buf = new uv_buf_t();
    buf->base = (char*)msg;
    buf->len = sizeof(__server_selection_msg);

    uv_write_t* req = new uv_write_t();
    uv_req_set_data((uv_req_t*)req, new std::tuple<Socks5Auth*, uv_buf_t*>(this, buf));
    uv_write(req, (uv_stream_t*)this->mp_client, buf, 1, Socks5Auth::write_callback_hello);
} //}
void Socks5Auth::__send_auth_status(uint8_t status) //{
{
    __socks5_user_authentication_reply* msg = new __socks5_user_authentication_reply();
    msg->m_version = 0x5;
    msg->m_status = status;
    uv_buf_t* buf = new uv_buf_t();
    buf->base = (char*)msg;
    buf->len = sizeof(__socks5_user_authentication_reply);

    uv_write_t* req = new uv_write_t();
    uv_req_set_data((uv_req_t*)req, new std::tuple<Socks5Auth*, uv_buf_t*>(this, buf));
    uv_write(req, (uv_stream_t*)this->mp_client, buf, 1, Socks5Auth::write_callback_id);
} //}
void Socks5Auth::__send_reply(uint8_t status) //{
{
    this->m_client_read_start = false;
    uv_read_stop((uv_stream_t*)this->mp_client);
    __server_reply_msg msg;
    msg.m_version = 0x5;
    msg.m_reply = (socks5_reply_type)status;
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
        size = this->m_servername.length() + 6;
        bufx = (char*)malloc(size);
        msg.m_addr_type = SOCKS5_ADDR_DOMAIN;
        memcpy(bufx, &msg, 4);
        memcpy(bufx + 4, this->m_servername.c_str(), this->m_servername.size());
        *(uint16_t*)(bufx + (size - 2)) = this->m_port; // FIXME
    }
    uv_buf_t* buf = new uv_buf_t();
    buf->base = (char*)bufx;
    buf->len = size;

    uv_write_t* req = new uv_write_t();
    uv_req_set_data((uv_req_t*)req, new std::tuple<Socks5Auth*, uv_buf_t*>(this, buf));
    uv_write(req, (uv_stream_t*)this->mp_client, buf, 1, Socks5Auth::write_callback_id);
} //}

void Socks5Auth::write_callback_hello(uv_write_t* req, int status) //{
{
    std::tuple<Socks5Auth*, uv_buf_t*>* x = 
        static_cast<decltype(x)>(uv_req_get_data((uv_req_t*)req));
    Socks5Auth* _this;
    uv_buf_t* buf;
    std::tie(_this, buf) = *x;
    delete x;
    delete (__server_selection_msg*)buf->base;
    delete buf;
    if(status != 0) _this->return_to_server();
} //}
void Socks5Auth::write_callback_id(uv_write_t* req, int status) //{
{
    std::tuple<Socks5Auth*, uv_buf_t*>* x = 
        static_cast<decltype(x)>(uv_req_get_data((uv_req_t*)req));
    Socks5Auth* _this;
    uv_buf_t* buf;
    std::tie(_this, buf) = *x;
    delete x;
    delete (__socks5_user_authentication_reply*)buf->base;
    delete buf;
    if(status != 0) _this->return_to_server();
} //}
void Socks5Auth::write_callback_reply(uv_write_t* req, int status) //{
{
    std::tuple<Socks5Auth*, uv_buf_t*>* x = 
        static_cast<decltype(x)>(uv_req_get_data((uv_req_t*)req));
    Socks5Auth* _this;
    uv_buf_t* buf;
    std::tie(_this, buf) = *x;
    delete x;
    free(buf->base);
    delete buf;
    if(status != 0)
        _this->m_state = SOCKS5_INIT;
    _this->return_to_server();
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
    uv_handle_set_data((uv_handle_t*)this->mp_uv_tcp, this);
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
    sockaddr_in addr;

    uint32_t network_order_addr = k_htonl(this->bind_addr);

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
    return;
} //}

/** connection callback function */
void Server::on_connection(uv_stream_t* stream, int status) //{
{
    logger->debug("connection callback called");
    if(status < 0) {
        logger->warn("new connection error");
        return;
    }

    Server* _this = (Server*)uv_handle_get_data((uv_handle_t*)stream);
    uv_tcp_t* client = new uv_tcp_t();
    uv_tcp_init(_this->mp_uv_loop, client);

    if(uv_accept(stream, (uv_stream_t*)client) < 0) {
        logger->warn("accept new connection error");
        delete client;
        return;
    }
    Socks5Auth* auth = new Socks5Auth(client, _this->m_config, Server::on_authentication, _this);
    _this->m_auths[auth] = true;
} //}

void Server::on_authentication(int status, Socks5Auth* self_ref, 
        const std::string& addr, uint16_t port,
        uv_tcp_t* con, void* data) //{
{
    Server* _this = (Server*)data;
    assert(_this->m_auths.find(self_ref) != _this->m_auths.end());
    _this->m_auths.erase(_this->m_auths.find(self_ref));
    delete self_ref;
    if(status <= 0) {
        uv_close((uv_handle_t*)con, delete_closed_handle);
        return;
    }

    _this->dispath_base_on_addr(addr, port ,con);
} //}

void Server::dispath_base_on_addr(const std::string& addr, uint16_t port, uv_tcp_t* con) //{
{
    this->dispath_bypass(addr, port, con);
} //}

void Server::dispath_bypass(const std::string& addr, uint16_t port, uv_tcp_t* con) //{
{
    RelayConnection* relay = new RelayConnection(this, this->mp_uv_loop, con, addr, port);
    this->m_relay[relay] = true;
    relay->run();
} //}

void Server::close_relay(RelayConnection* relay) //{
{
    assert(this->m_relay.find(relay) != this->m_relay.end());
    this->m_relay.erase(this->m_relay.find(relay));
    delete relay;
} //}
//}


//                class RelayConnection                       //{
RelayConnection::RelayConnection(Server* kserver, uv_loop_t* loop, uv_tcp_t* tcp_client, const std::string& server, uint16_t port) //{
{
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

    uv_handle_set_data((uv_handle_t*)this->mp_tcp_client, this);
}
//}

void RelayConnection::run() //{
{
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
        uv_req_set_data((uv_req_t*)&req, new std::tuple<bool, RelayConnection*>(false, this));
        RelayConnection::getaddrinfo_cb(&req, 0, &info);
    } else {
        struct addrinfo hints;
        hints.ai_family = AF_INET;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = 0;

        uv_getaddrinfo_t* p_req = new uv_getaddrinfo_t();
        uv_req_set_data((uv_req_t*)p_req, new std::tuple<bool, RelayConnection*>(true, this));

        uv_getaddrinfo(this->mp_loop, p_req, RelayConnection::getaddrinfo_cb, this->m_server.c_str(), "80", &hints);
    }
} //}

void RelayConnection::close() //{
{
    this->m_error = true;
    if(this->m_server_start_read) {
        uv_read_stop((uv_stream_t*)this->mp_tcp_server);
        this->m_server_start_read = false;
    }
    if(this->m_client_start_read) {
        uv_read_stop((uv_stream_t*)this->mp_tcp_client);
        this->m_client_start_read = false;
    }
    if(this->m_in_buffer == 0 && this->m_out_buffer == 0) {
        // TODO inform superior object
        uv_close((uv_handle_t*)this->mp_tcp_server, delete_closed_handle);
        this->mp_tcp_server = nullptr;
        uv_close((uv_handle_t*)this->mp_tcp_client, delete_closed_handle); // FIXME
        this->mp_tcp_client = nullptr;
        return this->m_kserver->close_relay(this);
    }
} //}

void RelayConnection::__connect_to(const sockaddr* addr) //{
{
    uv_connect_t* req = new uv_connect_t();
    uv_req_set_data((uv_req_t*)req, this);
    uv_tcp_t* tcp = new uv_tcp_t();
    uv_tcp_init(this->mp_loop, tcp);
    this->mp_tcp_server = tcp;
    uv_handle_set_data((uv_handle_t*)this->mp_tcp_server, this);
    uv_tcp_connect(req, tcp, addr, RelayConnection::connect_server_cb);
} //}

// static
void RelayConnection::getaddrinfo_cb(uv_getaddrinfo_t* req, int status, struct addrinfo* res) //{
{
    struct addrinfo *a;
    struct sockaddr_in* m;

    bool clean;
    RelayConnection* _this;
    std::tuple<bool, RelayConnection*>* msg =
        (std::tuple<bool, RelayConnection*>*)uv_req_get_data((uv_req_t*)req);
    std::tie(clean, _this) = *msg;
    if(clean) delete req;
    delete msg;

    if(status == UV_ECANCELED || status < 0) {
        logger->warn("dns query be cancelled");
        // TODO send a close packet
        if(clean) uv_freeaddrinfo(res);
        return;
    }
    for(a = res; a != nullptr; a = a->ai_next) {
        if(sizeof(struct sockaddr_in) != a->ai_addrlen) {
            logger->info("query dns get an address that isn't ipv4 address");
            std::cout << "problem" << std::endl;
            continue;
        } else break;
        /*
           char* addr = inet_ntoa(m->sin_addr);
           std::cout << "address: " << addr << std::endl;
           */
    }
    if(a == nullptr) {
        logger->warn("query dns doesn't get an ipv4 address");
        // TODO send a close packet
        if(clean) uv_freeaddrinfo(res);
        return;
    }
    m = (struct sockaddr_in*)a->ai_addr; // FIXME
    logger->info("used ipv4 address: %s", ip4_to_str(m->sin_addr.s_addr));
    m->sin_port = _this->m_port;
    _this->__connect_to((sockaddr*)m);
    if(clean) uv_freeaddrinfo(res);
} //}

void RelayConnection::connect_server_cb(uv_connect_t* req, int status) //{
{
    RelayConnection* _this = (RelayConnection*)uv_req_get_data((uv_req_t*)req);
    delete req;
    if(status != 0) {
        // TODO close connection
        uv_close((uv_handle_t*) _this->mp_tcp_server, delete_closed_handle);
        _this->mp_tcp_server = nullptr;
        _this->close();
        return;
    }
    _this->__start_relay();
} //}

void RelayConnection::__start_relay() //{
{
    this->__relay_client_to_server();
    this->__relay_server_to_client();
} //}

void RelayConnection::__relay_client_to_server() //{
{
    assert(this->m_client_start_read == false);
    uv_read_start((uv_stream_t*)this->mp_tcp_client, 
            malloc_cb, 
            RelayConnection::client_read_cb);
    this->m_client_start_read = true;
} //}
void RelayConnection::__relay_server_to_client() //{
{
    assert(this->m_server_start_read == false);
    uv_read_start((uv_stream_t*)this->mp_tcp_server, 
            malloc_cb, 
            RelayConnection::server_read_cb);
    this->m_server_start_read = true;
} //}

void RelayConnection::client_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    assert(nread == buf->len);
    if(nread == 0) {
        // TODO
        return;
    }
    RelayConnection* _this = (RelayConnection*)uv_handle_get_data((uv_handle_t*)stream);
    uv_write_t* req = new uv_write_t();
    uv_req_set_data((uv_req_t*)req, new std::tuple<RelayConnection*, const uv_buf_t*>(_this, buf));
    _this->m_out_buffer += buf->len;
    uv_write(req, (uv_stream_t*)_this->mp_tcp_server, buf, 1, RelayConnection::server_write_cb);

    if(_this->m_out_buffer > RELAY_MAX_BUFFER_SIZE) {
        uv_read_stop(stream);
        _this->m_client_start_read = false;
    }
} //}
void RelayConnection::server_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    assert(nread == buf->len);
    if(nread == 0) {
        // TODO whether connection error
        return;
    }
    RelayConnection* _this = (RelayConnection*)uv_handle_get_data((uv_handle_t*)stream);
    uv_write_t* req = new uv_write_t();
    uv_req_set_data((uv_req_t*)req, new std::tuple<RelayConnection*, const uv_buf_t*>(_this, buf));
    _this->m_in_buffer += buf->len;
    uv_write(req, (uv_stream_t*)_this->mp_tcp_client, buf, 1, RelayConnection::client_write_cb);

    if(_this->m_in_buffer > RELAY_MAX_BUFFER_SIZE) {
        uv_read_stop(stream);
        _this->m_server_start_read = false;
    }
} //}

void RelayConnection::server_write_cb(uv_write_t* req, int status) //{
{
    std::tuple<RelayConnection*, const uv_buf_t*>* x = 
        static_cast<decltype(x)>(uv_req_get_data((uv_req_t*)req));
    RelayConnection* _this;
    const uv_buf_t* buf;
    std::tie(_this, buf) = *x;
    delete x;

    _this->m_out_buffer -= buf->len;
    free(buf->base);
    free((void*)buf);

    if(status != 0 || _this->m_error) {
        // TODO
        _this->m_error = true;
        _this->close();
        return;
    }

    if(!_this->m_client_start_read && _this->m_out_buffer < RELAY_MAX_BUFFER_SIZE)
        _this->__relay_client_to_server();
} //}
void RelayConnection::client_write_cb(uv_write_t* req, int status) //{
{
    std::tuple<RelayConnection*, const uv_buf_t*>* x = 
        static_cast<decltype(x)>(uv_req_get_data((uv_req_t*)req));
    RelayConnection* _this;
    const uv_buf_t* buf;
    std::tie(_this, buf) = *x;
    delete x;

    _this->m_out_buffer -= buf->len;
    free(buf->base);
    free((void*)buf);

    if(status != 0 || _this->m_error) {
        // TODO
        _this->m_error = true;
        _this->close();
        return;
    }
    if(!_this->m_server_start_read && _this->m_in_buffer < RELAY_MAX_BUFFER_SIZE)
        _this->__relay_server_to_client();
} //}
//}

}

