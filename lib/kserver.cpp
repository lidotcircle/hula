#include "../include/kserver.h"
#include "../include/logger.h"
#include "../include/utils.h"

#include <uv.h>

#include <stdlib.h>

#include <tuple>


namespace KProxyServer {

/**                     class Server                  *///{

Server::Server(uv_loop_t* loop, uint32_t bind_addr, uint16_t bind_port): //{
    bind_addr(bind_addr),
    bind_port(bind_port),
    mp_uv_loop(loop)
{
    this->mp_uv_tcp = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    uv_tcp_init(this->mp_uv_loop, this->mp_uv_tcp);

    this->tsl_list = nullptr;
} //}

int Server::listen() //{ 
{
    logger.debug("call Server::listen()");
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr = {.s_addr = this->bind_addr};
    addr.sin_port = this->bind_port;
    int s = uv_tcp_bind(this->mp_uv_tcp, (sockaddr*)&addr, 0);
    if(s != 0) {
        logger.error("bind error %s:%d", ip4_to_str(this->bind_addr), this->bind_port);
        return s;
    }
    s = uv_listen((uv_stream_t*)this->mp_uv_tcp, 100, nullptr);
    if(s != 0) {
        logger.error("listen error %s:%d", ip4_to_str(this->bind_addr), this->bind_port);
        return s;
    }
    logger.debug("listen at %s:%d", ip4_to_str(this->bind_addr), this->bind_port);
    return s;
} //}

int Server::close() //{
{
    return 0;
} //}

//}

/**                     class ClientConnectionProxy                  *///{
//}

/**             class ServerToNetConnection            */ //{
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

ServerToNetConnection::ServerToNetConnection(const sockaddr* addr, ConnectionId id, ClientConnectionProxy* p, uv_read_cb rcb) //{
{
    Logger::debug("ServerToNetConnectio::construtor() called new proxy connection");
    this->m_connectionWrapper = p;
    this->m_read_callback = rcb;
    this->id = id;
    this->used_buffer_size = 0;
    this->mp_tcp = new uv_tcp_t();

    uv_handle_set_data((uv_handle_t*)this->mp_tcp, this);

    uv_connect_t* p_req = new uv_connect_t();
    uv_req_set_data((uv_req_t*)p_req, this);

    uv_tcp_connect(p_req, this->mp_tcp, addr, 
                   ServerToNetConnection::tcp_connect_callback);
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

    return uv_write(p_req, (uv_stream_t*)this->mp_tcp, bufs, nbufs, 
            [](uv_write_t* req, int status) -> void {
                data_type* x = static_cast<data_type*>(uv_req_get_data((uv_req_t*)req));
                ServerToNetConnection* _this = std::get<0>(*x);
                uv_write_cb cb = std::get<1>(*x);
                size_t size = std::get<2>(*x);
                delete x;
                
                _this->used_buffer_size -= size;

                cb(req, status);
            });
} //}

int ServerToNetConnection::realy_back(uv_buf_t buf) //{
{
    return 0;
} //}

ServerToNetConnection::~ServerToNetConnection() //{
{
    Logger::debug("ServerToNetConnection:deconstructor() called");
    delete this->mp_tcp;
    this->mp_tcp = nullptr;
} //}
//}

}
