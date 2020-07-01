#pragma once

#include <string>
#include <vector>
#include <tuple>
#include <map>
#include <unordered_set>
#include <set>

#include "robuf.h"
#include "utils.h"
#include "events.h"
#include "config_file.h"
#include "dlinkedlist.hpp"
#include "socks5.h"
#include "object_manager.h"

#include "stream.hpp"

#define SINGLE_TSL_MAX_CONNECTION (1 << 6)

// forward declaration
namespace UVC {struct UVCBaseClient;}


#define NS_PROXY_CLIENT_START namespace KProxyClient {
#define NS_PROXY_CLIENT_END   }


NS_PROXY_CLIENT_START

class Socks5ServerAbstraction {
    public:
        virtual void netAccept() = 0;
        virtual void netReject() = 0;

        virtual void start() = 0;

        virtual void* transferStream() = 0;

        virtual void close() = 0;
        inline virtual ~Socks5ServerAbstraction() {}
};

class Socks5RequestProxy {
    public:
        virtual void close() = 0;
        virtual void connectToAddr() = 0;
        virtual void run(Socks5ServerAbstraction*) = 0;

        virtual void getStream(void*) = 0;

        inline virtual ~Socks5RequestProxy() {}
};

class RelayAbstraction: public Socks5RequestProxy {
};

class ClientProxyAbstraction: public Socks5RequestProxy, virtual protected EBStreamAbstraction, virtual public CallbackManager {
    public:
        virtual void pushData(ROBuf) = 0;
        virtual void startClientRead() = 0;
        virtual void stopClientRead() = 0;
        virtual void ServerEnd() = 0;
        virtual void connectSuccess() = 0;
        virtual void connectFail() = 0;
};

class ProxyMultiplexerAbstraction: virtual protected EBStreamAbstraction, virtual public CallbackManager {
    public:
        virtual void close() = 0;

        virtual bool    full() = 0;
        virtual uint8_t get_id() = 0;

        virtual bool connected() = 0;
};

class Server;
class ConnectionProxy;
class RelayConnection;
class ClientConnection;

NS_PROXY_CLIENT_END
