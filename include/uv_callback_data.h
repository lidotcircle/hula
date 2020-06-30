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
    inline Base(){}
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
    inline RelayConnection$connect$uv_getaddrinfo(KProxyClient::Server* server, bool is_uv, 
            KProxyClient::RelayConnection* _this): 
        UVCBaseClient(server), is_uv(is_uv), _this(_this){}
};

struct RelayConnection$__connect_to$uv_tcp_connect: public UVCBaseClient {
    KProxyClient::RelayConnection* _this;
    inline RelayConnection$__connect_to$uv_tcp_connect(KProxyClient::Server* server, KProxyClient::RelayConnection* _this): 
        UVCBaseClient(server), _this(_this){}
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
    inline ConnectionProxy$connect_to_remote_server$uv_getaddrinfo(
            KProxyClient::Server* server, 
            KProxyClient::ConnectionProxy* _this, 
            bool clean): 
        UVCBaseClient(server), _this(_this), _clean(clean){}
};

struct ConnectionProxy$connect_to_with_sockaddr$uv_tcp_connect: public UVCBaseClient {
    KProxyClient::ConnectionProxy* _this;
    inline ConnectionProxy$connect_to_with_sockaddr$uv_tcp_connect(
            KProxyClient::Server* server, 
            KProxyClient::ConnectionProxy* _this): 
        UVCBaseClient(server), _this(_this){}
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

