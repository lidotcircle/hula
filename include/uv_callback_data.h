#pragma once

#include "kclient.h"
#include "kserver.h"

// UVCCLIENT //{
namespace UVC {

/** struct naming convention
 *     <class>$<method>$<uv_function>
 *  except when <method> is constructor, naming with <class>$<uv_function>
 *  xxxx mean '.*'
 */

struct Base {
    bool should_run;
    inline Base(): should_run(true){}
    inline virtual ~Base(){};
};

struct UVCBaseClient: public Base {
    KProxyClient::Server* _server;
    inline UVCBaseClient(KProxyClient::Server* _server): Base(), _server(_server){}
};

struct Socks5Auth$uv_read_start: public UVCBaseClient {
    KProxyClient::Socks5Auth* _this;
    inline Socks5Auth$uv_read_start(KProxyClient::Server* server, 
            KProxyClient::Socks5Auth* _this): UVCBaseClient(server), _this(_this){}
};

struct Socks5Auth$__send_selection_method$uv_write: public UVCBaseClient {
    KProxyClient::Socks5Auth* _this;
    uv_buf_t* uv_buf;
    inline Socks5Auth$__send_selection_method$uv_write(KProxyClient::Server* server, KProxyClient::Socks5Auth* _this, 
            uv_buf_t* buf): UVCBaseClient(server), _this(_this), uv_buf(buf){}
};

struct Socks5Auth$__send_auth_status$uv_write: public UVCBaseClient {
    KProxyClient::Socks5Auth* _this;
    uv_buf_t* uv_buf;
    inline Socks5Auth$__send_auth_status$uv_write(KProxyClient::Server* server, 
            KProxyClient::Socks5Auth* _this, 
            uv_buf_t* buf): UVCBaseClient(server), _this(_this), uv_buf(buf){}
};

struct Socks5Auth$__send_reply$uv_write: public UVCBaseClient {
    KProxyClient::Socks5Auth* _this;
    uv_buf_t* uv_buf;
    uint8_t reply;
    Socks5Auth$__send_reply$uv_write(KProxyClient::Server* server, KProxyClient::Socks5Auth* _this, 
            uv_buf_t* buf, uint8_t reply): UVCBaseClient(server), _this(_this), uv_buf(buf), reply(reply){}
};

struct KProxyClient$Server$uv_listen: public UVCBaseClient {
    KProxyClient::Server* _this;
    inline KProxyClient$Server$uv_listen(KProxyClient::Server* _this): UVCBaseClient(_this), _this(_this){}
};

struct RelayConnection$connect$uv_getaddrinfo: public UVCBaseClient {
    bool is_uv;
    KProxyClient::RelayConnection* _this;
    KProxyClient::Socks5Auth* _socks5;
    inline RelayConnection$connect$uv_getaddrinfo(KProxyClient::Server* server, bool is_uv, 
            KProxyClient::RelayConnection* _this, 
            KProxyClient::Socks5Auth* socks5): UVCBaseClient(server), is_uv(is_uv), _this(_this), _socks5(socks5){}
};

struct RelayConnection$__connect_to$uv_tcp_connect: public UVCBaseClient {
    KProxyClient::RelayConnection* _this;
    KProxyClient::Socks5Auth* _socks5;
    inline RelayConnection$__connect_to$uv_tcp_connect(KProxyClient::Server* server, KProxyClient::RelayConnection* _this, 
            KProxyClient::Socks5Auth* socks5): UVCBaseClient(server), _this(_this), _socks5(socks5){}
};

struct RelayConnection$xxxx_read_cb$uv_write: public UVCBaseClient {
    KProxyClient::RelayConnection* _this;
    uv_buf_t* uv_buf;
    inline RelayConnection$xxxx_read_cb$uv_write(KProxyClient::Server* server, KProxyClient::RelayConnection* _this, 
            uv_buf_t* uv_buf): UVCBaseClient(server),_this(_this), uv_buf(uv_buf){}
};

struct ConnectionProxy$connect_to_remote_server$uv_getaddrinfo: public UVCBaseClient {
    KProxyClient::ConnectionProxy* _this;
    bool _clean;
    KProxyClient::ConnectionProxy::ConnectCallback _cb;
    void* _cb_data;
    inline ConnectionProxy$connect_to_remote_server$uv_getaddrinfo(
            KProxyClient::Server* server, 
            KProxyClient::ConnectionProxy* _this, 
            bool clean,
            KProxyClient::ConnectionProxy::ConnectCallback _cb, void* _cb_data): 
        UVCBaseClient(server), _this(_this), _clean(clean), _cb(_cb), _cb_data(_cb_data){}
};

struct ConnectionProxy$connect_to_with_sockaddr$uv_tcp_connect: public UVCBaseClient {
    KProxyClient::ConnectionProxy* _this;
    KProxyClient::ConnectionProxy::ConnectCallback _cb;
    void* _cb_data;
    inline ConnectionProxy$connect_to_with_sockaddr$uv_tcp_connect(
            KProxyClient::Server* server, 
            KProxyClient::ConnectionProxy* _this,
            KProxyClient::ConnectionProxy::ConnectCallback _cb,
            void* _cb_data): 
        UVCBaseClient(server), _this(_this), _cb(_cb), _cb_data(_cb_data){}
};

struct ConnectionProxy$_write$uv_write: public UVCBaseClient {
    KProxyClient::ConnectionProxy* _this;
    KProxyClient::ConnectionProxy::WriteCallback _cb;
    void* _data;
    ROBuf* _mem_holder;
    uv_buf_t* _uv_buf;

    ConnectionProxy$_write$uv_write(
            KProxyClient::Server* server, 
            KProxyClient::ConnectionProxy* proxy, 
            KProxyClient::ConnectionProxy::WriteCallback cb,
            void* data, ROBuf* mem_holder, uv_buf_t* uv_buf): 
        UVCBaseClient(server), _this(proxy), _cb(cb), 
        _data(data), _mem_holder(mem_holder), _uv_buf(uv_buf) {}
};

struct ConnectionProxy$new_connection$uv_timer_start: public UVCBaseClient {
    KProxyClient::ConnectionProxy* _this;
    void* _data;
    inline ConnectionProxy$new_connection$uv_timer_start(KProxyClient::Server* server,
            KProxyClient::ConnectionProxy* _this, void* data):
        UVCBaseClient(server), _this(_this), _data(data) {}
};

struct ClientConnection$write_to_client_callback$uv_write: public UVCBaseClient {
    KProxyClient::ClientConnection::__proxyWriteInfo* _info;
    ROBuf* _rbuf;
    uv_buf_t* _ubuf;
    inline ClientConnection$write_to_client_callback$uv_write(KProxyClient::Server* server,
            KProxyClient::ClientConnection::__proxyWriteInfo* info,
            ROBuf* rbuf, uv_buf_t* ubuf):
        UVCBaseClient(server), _info(info), _rbuf(rbuf), _ubuf(ubuf) {}
};

} //}

// UVCSERVER //{
namespace UVC {
    
struct UVCBaseServer: public UVC::Base {
    KProxyServer::ClientConnectionProxy* _proxy;
    inline UVCBaseServer(KProxyServer::ClientConnectionProxy* _server): Base(), _proxy(_server){}
};

struct ServerToNetConnection$__connect$uv_getaddrinfo: public UVC::UVCBaseServer {
    KProxyServer::ServerToNetConnection* _this;
    uint16_t _port;
    bool _clean;

    inline ServerToNetConnection$__connect$uv_getaddrinfo(KProxyServer::ClientConnectionProxy* _server,
            KProxyServer::ServerToNetConnection* _this, uint16_t port, bool clean): 
        UVCBaseServer(_server), _this(_this), _port(port), _clean(clean){}
};

struct ServerToNetConnection$__connect_with_sockaddr$uv_tcp_connect: public UVCBaseServer {
    KProxyServer::ServerToNetConnection* _this;
    inline ServerToNetConnection$__connect_with_sockaddr$uv_tcp_connect(
            KProxyServer::ClientConnectionProxy* proxy,
            KProxyServer::ServerToNetConnection* _this): UVCBaseServer(proxy), _this(_this){}
};

struct ClientConnectionProxy$_write$uv_write: public UVCBaseServer {
    KProxyServer::ClientConnectionProxy* _this;
    KProxyServer::ClientConnectionProxy::WriteCallback _cb;
    void* _data;
    ROBuf* _mem_holder;
    uv_buf_t* _uv_buf;

    ClientConnectionProxy$_write$uv_write(
            KProxyServer::ClientConnectionProxy* proxy, 
            KProxyServer::ClientConnectionProxy::WriteCallback cb,
            void* data, ROBuf* mem_holder, uv_buf_t* uv_buf): 
        UVCBaseServer(proxy), _this(proxy), _cb(cb), 
        _data(data), _mem_holder(mem_holder), _uv_buf(uv_buf) {}
};

struct ServerToNetConnection$PushData$uv_write: public UVCBaseServer {
    KProxyServer::ServerToNetConnection* _this;
    ROBuf* _robuf;
    uv_buf_t* _uv_buf;
    inline ServerToNetConnection$PushData$uv_write(KProxyServer::ClientConnectionProxy* _proxy,
           KProxyServer::ServerToNetConnection* _this, ROBuf* _robuf, uv_buf_t* uv_buf):
       UVCBaseServer(_proxy), _this(_this), _robuf(_robuf), _uv_buf(uv_buf) {} 
};

} //}

