#include "./object_manager.h"
#include "./kserver_multiplexing.h"

#include "./kclient_socks5.h"


#define NS_CBD_START namespace CBD {
#define NS_CBD_END   }

NS_CBD_START
using namespace KProxyServer;

struct SBase: public CallbackPointer {};
struct ClientConnectionProxy$__write$_write: public SBase {
    ClientConnectionProxy*               _this;
    ClientConnectionProxy::WriteCallback _cb;
    void*                                _data;
    inline ClientConnectionProxy$__write$_write(ClientConnectionProxy* _this, ClientConnectionProxy::WriteCallback cb, void* data):
         _this(_this), _cb(cb), _data(data) {}
};
struct ServerToNetConnection$__connect$getaddrinfo: public SBase {
    ServerToNetConnection*                   _this;
    bool                                     _clean;
    uint16_t                                 _port;
    inline ServerToNetConnection$__connect$getaddrinfo(ServerToNetConnection* _this, bool clean, uint16_t port):
         _this(_this), _clean(clean), _port(port) {}
};
struct ServerToNetConnection$__connect_with_sockaddr$connect: public SBase {
    ServerToNetConnection* _this;
    inline ServerToNetConnection$__connect_with_sockaddr$connect(ServerToNetConnection* _this): _this(_this) {}
};
struct ServerToNetConnection$write_to_user$write: public SBase {
    ServerToNetConnection* _this;
    inline ServerToNetConnection$write_to_user$write(ServerToNetConnection* _this): _this(_this) {}
};
struct ServerToNetConnection$PushData$write: public SBase {
    ServerToNetConnection* _this;
    inline ServerToNetConnection$PushData$write(ServerToNetConnection* _this): _this(_this) {}
};

NS_CBD_END

NS_CBD_START
using namespace KProxyClient;
struct CBase: public CallbackPointer {};

struct Socks5Auth$__send_selection_method$_write: public CBase {
    Socks5Auth* _this;
    inline Socks5Auth$__send_selection_method$_write(Socks5Auth* _this): _this(_this) {}
};
struct Socks5Auth$__send_auth_status$_write: public CBase {
    Socks5Auth* _this;
    inline Socks5Auth$__send_auth_status$_write(Socks5Auth* _this): _this(_this) {}
};
struct Socks5Auth$__send_reply$_write: public CBase {
    Socks5Auth* _this;
    uint8_t     _reply;
    inline Socks5Auth$__send_reply$_write(Socks5Auth* _this, uint8_t reply): _this(_this), _reply(reply) {}
};

NS_CBD_END


