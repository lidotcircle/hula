#include "../include/kserver.h"
#include "../include/logger.h"
#include "../include/utils.h"
#include "../include/dlinkedlist.hpp"
#include "../include/kpacket.h"
#include "../include/robuf.h"

#include <uv.h>

#include <stdlib.h>
#include <assert.h>

#include <tuple>

#define CONNECTION_MAX_BUFFER_SIZE (2 * 1024 * 1024) // 2M


namespace KProxyServer {
using Logger::logger;

/**                     class Server                  *///{

Server::Server(uv_loop_t* loop, uint32_t bind_addr, uint16_t bind_port): //{
    bind_addr(bind_addr),
    bind_port(bind_port),
    mp_uv_loop(loop)
{
    this->mp_uv_tcp = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    uv_tcp_init(this->mp_uv_loop, this->mp_uv_tcp);

    uv_handle_set_data((uv_handle_t*)this->mp_uv_tcp, this);

    this->tsl_list = nullptr;
} //}

int Server::listen() //{ 
{
    logger->debug("call Server::listen()");
    sockaddr_in addr;
    uv_ip4_addr(ip4_to_str(this->bind_addr), this->bind_port, &addr);
    int s = uv_tcp_bind(this->mp_uv_tcp, (sockaddr*)&addr, 0);
    if(s != 0) {
        logger->error("bind error %s:%d", ip4_to_str(this->bind_addr), this->bind_port);
        return s;
    }
    s = uv_listen((uv_stream_t*)this->mp_uv_tcp, DEFAULT_BACKLOG, Server::on_connection);
    if(s != 0) {
        logger->error("listen error %s:%d", ip4_to_str(this->bind_addr), this->bind_port);
        return s;
    }
    logger->debug("listen at %s:%d", ip4_to_str(this->bind_addr), this->bind_port);
    return 0;
} //}

int Server::close() //{
{
    return 0;
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
    uv_tcp_t* client = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    uv_tcp_init(_this->mp_uv_loop, client);

    if(uv_accept(stream, (uv_stream_t*)client) < 0) {
        logger->warn("accept new connection error");
        return;
    }

    connectionType* cb_arg = new connectionType(client);
    _this->emit("connection", cb_arg);
    delete cb_arg;

    _this->dispatch_new_connection(client);
    return;
} //}

/** dispatch connection to wrapper object */
void Server::dispatch_new_connection(uv_tcp_t* connection) //{
{
    DLinkedList<ClientConnectionProxy*>* new_entry
        = DLinkedList_insert<ClientConnectionProxy*>(&this->tsl_list, nullptr);
    ClientConnectionProxy* newProxy = new ClientConnectionProxy(this, connection, new_entry);
    new_entry->value = newProxy;
} //}
//}

/**                     class ClientConnectionProxy                  *///{

/** constructor */
ClientConnectionProxy::ClientConnectionProxy(Server* server, uv_tcp_t* connection, 
                                             DLinkedList<ClientConnectionProxy*>* list_entry) //{
{
    this->m_server = server;
    this->m_connection = connection;
    this->m_entry = list_entry;
    this->mp_loop = uv_handle_get_loop((uv_handle_t*)this->m_connection);

    uv_handle_set_data((uv_handle_t*)this->m_connection, this);

    int s = uv_read_start((uv_stream_t*)this->m_connection, 
                  ClientConnectionProxy::malloc_cb, 
                  ClientConnectionProxy::read_cb);

    if(s < 0) {
        logger->error("start read stream fail");
        return;
        // TODO release connection
    }

    this->server_tsl_handshake();
} //}

void ClientConnectionProxy::malloc_cb(uv_handle_t* h, size_t suggested_size, uv_buf_t* out) //{
{
    out->base = (char*)malloc(suggested_size);
    out->len  = suggested_size;
    return;
} //}

void ClientConnectionProxy::read_cb  (uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    ClientConnectionProxy* proxy = 
        (ClientConnectionProxy*)uv_handle_get_data((uv_handle_t*)stream);
    assert(proxy != nullptr);
    proxy->dispatch_new_encrypted_data(nread,buf);
} //}

void ClientConnectionProxy::dispatch_new_encrypted_data(ssize_t nread, const uv_buf_t* buf) //{
{
    // pass
    this->dispatch_new_unencrypted_data(nread, buf);
} //}

void ClientConnectionProxy::dispatch_new_unencrypted_data(ssize_t nread, const uv_buf_t* buf) //{
{
    ROBuf v(buf->base, buf->len);
    auto result = decode_all_packet(this->remains, &v);
    std::vector<std::tuple<ROBuf*, PacketOp, uint8_t>> x;
    ROBuf* y;
    std::tie(x, y) = result;

    this->remains->unref();
    delete this->remains;
    v.unref();
    this->remains = y;

    for(auto& z: x) {
        ROBuf* a;
        PacketOp b;
        uint8_t id;
        std::tie(a, b, id) = z;

        switch(b) {
            case PACKET_OP_NEW:
                this->dispatch_new(id, a);
                break;
            case PACKET_OP_REG:
                this->dispatch_reg(id, a);
                break;
            case PACKET_OP_CLOSE:
                this->dispatch_close(id, a);
                break;
            case PACKET_OP_RESERVED:
            default:
                logger->warn("unexcepted packet which use reserved opcode");
                break;
        }
    }
} //}

static int find_semicolon(char* pair) //{
{
    int i = 0;
    for(;i<strlen(pair); i++) {
        if(pair[i] == ':') break;
        if(pair[i] == '\0') return -1;
    }
    return i;
} //}
static bool str_to_port(char* str, uint16_t* port_out) //{
{
    uint16_t x = atoi(str);
    if(x != 0) {
        *port_out = k_ntohs(x);
        return true;
    }
    int i = 0;
    while(str[i] != '\0') {
        if(str[i] != '0')
            return false;
        i++;
    }
    *port_out = 0;
    return true;
} //}
void ClientConnectionProxy::to_internet_ipv4_connection(const sockaddr_in* addr, uint8_t id) //{
{
    logger->info("establish a new connection to %s:%d", ip4_to_str(addr->sin_addr.s_addr), addr->sin_port);
    ServerToNetConnection* con = new ServerToNetConnection(this->mp_loop, (sockaddr*)addr, id, this); // TODO
    this->m_map[id] = con;
} //}
/*
 * the request has format like | addr_len |    address:port   | 
 *                             |  16bit   |   addr_len bytes  |*/
void ClientConnectionProxy::dispatch_new(uint8_t id, ROBuf* buf) //{
{
    assert(id < 1 << 6);
    if(this->m_map.find(id) != this->m_map.end()) {
        logger->warn("bad connection id");
        // TODO close current tls connection
        return;
    }

    uint16_t len = 0;
    len = k_ntohs(*(u_int16_t*)buf->base());
    if(len + sizeof(len) != buf->size()) {
        logger->warn("invalid packet with length %d", len);
        // TODO send a close packet to id
        return;
    }

    char* addr_pair = (char*)malloc(len + 1);
    memcpy(addr_pair, buf->base(), len);
    addr_pair[len] = '0';
    int semicolon = find_semicolon(addr_pair);
    if(semicolon < 0) {
        logger->warn("invalid address:port pair <%s>", addr_pair);
        // TODO send a close packet to id
        return;
    }
    addr_pair[semicolon++] = '\0';

    uint16_t port;
    if(str_to_port(addr_pair + semicolon, &port) == false) {
        logger->warn("incorrect port: %s", addr_pair + semicolon);
        // TODO send a close packet to id
        return;
    }

    uint32_t addr;
    if(str_to_ip4(addr_pair, &addr)) {
        struct sockaddr_in addr_in;
        uv_ip4_addr(addr_pair, port, &addr_in);
        this->to_internet_ipv4_connection(&addr_in, id);
    } else {
        this->query_dns_connection(addr_pair, port, id);
    }
    return;
} //}

void ClientConnectionProxy::dispatch_reg(uint8_t id, ROBuf* buf) //{
{
    assert(this->m_map.find(id) != this->m_map.end());
    ServerToNetConnection* s = this->m_map[id];
    uv_buf_t bufx;
    bufx.base = (char*)buf->base();
    bufx.len = buf->size();
    s->write(&bufx);
} //}

void ClientConnectionProxy::dispatch_close(uint8_t id, ROBuf* buf) //{
{
    assert(this->m_map.find(id) != this->m_map.end());
    ServerToNetConnection* s = this->m_map[id];
    if( buf->size() > 0) {
        char* reason = (char*)malloc(buf->size() + 1);
        memcpy(reason, buf->base(), buf->size());
        reason[buf->size()] = '\0';
        logger->info("close connection because %s", reason);
        free(reason);
    }
    s->close();
} //}

// static 
void ClientConnectionProxy::query_dns_cb(uv_loop_t* loop, uv_getaddrinfo_t* req, int status, struct addrinfo* res) //{
{
    struct addrinfo *a;
    struct sockaddr_in* m;

    ClientConnectionProxy* _this;
    uint16_t port;
    uint8_t id;
    std::tuple<ClientConnectionProxy*, uint16_t, uint8_t>* msg =
        (std::tuple<ClientConnectionProxy*, uint16_t, uint8_t>*)uv_req_get_data((uv_req_t*)req);
    std::tie(_this, port, id) = *msg;
    assert(id < 1 << 6);
    delete msg;

    if(status == UV_ECANCELED || status < 0) {
        logger->warn("dns query be cancelled");
        // TODO send a close packet
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
        return;
    }
    m = (struct sockaddr_in*)a->ai_addr;
    logger->info("used ipv4 address: %s", ip4_to_str(m->sin_addr.s_addr));
    m->sin_port = port;
    _this->to_internet_ipv4_connection(m, id);
} //}

void ClientConnectionProxy::query_dns_connection(char* addr, uint16_t port, uint8_t id) //{
{
    struct addrinfo hints;
    hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;

    uv_getaddrinfo_t* p_req = (uv_getaddrinfo_t*)malloc(sizeof(uv_getaddrinfo_t));
    uv_req_set_data((uv_req_t*)p_req, new std::tuple<ClientConnectionProxy*, uint16_t, uint8_t>(this, port, id));

    uv_getaddrinfo(this->mp_loop, p_req, [](uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    }, addr, "80", &hints);

} //}

void ClientConnectionProxy::server_tsl_handshake() //{
{
    // plain pass
    this->user_authenticate();
} //}

void ClientConnectionProxy::user_authenticate() //{
{
    // pass
    return;
} //}

//}

/**                     class ServerToNetConnection            */ //{
void ServerToNetConnection::tcp_read_callback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) //{
{
    if(nread < 0) {
        // TODO
    } else if (nread == 0) { // EOF
        // TODO
    }
    ServerToNetConnection* _this = (ServerToNetConnection*)uv_handle_get_data((uv_handle_t*)stream);
    _this->realy_back(*buf);
    return;
} //}
void ServerToNetConnection::tcp_connect_callback(uv_connect_t* req, int status) //{
{
    ServerToNetConnection* _this = (ServerToNetConnection*)uv_req_get_data((uv_req_t*)req);

    delete req;

    if(status < 0) {
        // TODO
    }

    uv_read_start((uv_stream_t*)_this->mp_tcp, 
            ServerToNetConnection::tcp_alloc_callback,
            ServerToNetConnection::tcp_read_callback
            );
} //}
void ServerToNetConnection::tcp_alloc_callback(uv_handle_t* req, size_t suggested_size, uv_buf_t* buf) //{
{
    buf->base = (char*)malloc(suggested_size);
    buf->len  = suggested_size;
    return;
} //}

ServerToNetConnection::ServerToNetConnection(uv_loop_t* loop, const sockaddr* addr, ConnectionId id, ClientConnectionProxy* p) //{
{
    Logger::debug("ServerToNetConnectio::construtor() called new proxy connection");
    this->m_connectionWrapper = p;
    this->id = id;
    this->used_buffer_size = 0;
    this->mp_loop = loop;
    this->mp_tcp = new uv_tcp_t();
    uv_tcp_init(this->mp_loop, this->mp_tcp);

    uv_handle_set_data((uv_handle_t*)this->mp_tcp, this);

    uv_connect_t* p_req = new uv_connect_t();
    uv_req_set_data((uv_req_t*)p_req, this);

    uv_tcp_connect(p_req, this->mp_tcp, addr, 
                   ServerToNetConnection::tcp_connect_callback);
} //}

// static
void ServerToNetConnection::tcp_write_callback(uv_write_t* req, int status) //{
{
    std::tuple<ServerToNetConnection*, uv_write_cb, size_t>* x 
        = static_cast<std::tuple<ServerToNetConnection*, uv_write_cb, size_t>*>(uv_req_get_data((uv_req_t*)req));
    ServerToNetConnection* _this = std::get<0>(*x);
    uv_write_cb cb = std::get<1>(*x);
    size_t size = std::get<2>(*x);
    delete x;

    _this->used_buffer_size -= size;

    if(status < 0) {
        // TODO close
        return;
    }

    if(cb != nullptr)
        cb(req, status);
} //}

int ServerToNetConnection::write(uv_buf_t bufs[], unsigned int nbufs, uv_write_cb cb) //{
{
    Logger::debug("ServerToNetConnection::write() called");
    using data_type = std::tuple<decltype(this), decltype(cb), size_t>;

    size_t size = 0;
    for(int i=0;i<nbufs;i++)
        size += bufs[i].len;
    this->used_buffer_size += size;

    uv_write_t* p_req = new uv_write_t();
    uv_req_set_data((uv_req_t*)p_req, new data_type(this, cb, size));

    uv_write(p_req, 
             (uv_stream_t*)this->mp_tcp, 
             bufs, 
             nbufs, 
             ServerToNetConnection::tcp_write_callback);

    return this->used_buffer_size > CONNECTION_MAX_BUFFER_SIZE ? -1 : 0;
} //}
int ServerToNetConnection::write(uv_buf_t* buf) //{
{
    return this->write(buf, 1, nullptr);
} //}

int ServerToNetConnection::realy_back(uv_buf_t buf) //{
{
    return 0;
} //}

void ServerToNetConnection::close() //{
{
    // TODO
} //}

ServerToNetConnection::~ServerToNetConnection() //{
{
    Logger::debug("ServerToNetConnection:deconstructor() called");
    delete this->mp_tcp;
    this->mp_tcp = nullptr;
} //}
//}

}
