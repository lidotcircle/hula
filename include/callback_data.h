#include "./object_manager.h"
#include "./kserver_multiplexer.h"

#include "./kclient_socks5.h"


#define NS_CBD_START namespace CBD {
#define NS_CBD_END   }

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


