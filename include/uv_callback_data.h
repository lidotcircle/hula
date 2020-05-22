#pragma once

#include "kclient.h"
#include "kserver.h"

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
    Socks5Auth$__send_reply$uv_write(KProxyClient::Server* server, KProxyClient::Socks5Auth* _this, 
            uv_buf_t* buf): UVCBaseClient(server), _this(_this), uv_buf(buf){}
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

}

