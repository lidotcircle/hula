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
#include "kclient_config.h"
#include "dlinkedlist.hpp"
#include "socks5.h"
#include "object_manager.h"
#include "StreamProvider_KProxyMultiplexer.h"

#include "stream.hpp"

#define SINGLE_TSL_MAX_CONNECTION (1 << 6)

// forward declaration
namespace UVC {struct UVCBaseClient;}


#define NS_PROXY_CLIENT_START namespace KProxyClient {
#define NS_PROXY_CLIENT_END   }


NS_PROXY_CLIENT_START

enum ConnectResult {
    SUCCEEDED = 0,
    SERVER_FAILURE,
    CONNECTION_NOT_ALLOW_BY_RULE_SET,
    NETWORK_UNREACHABLE,
    HOST_UNREACHABLE,
    CONNECTION_REFUSED,
    TTL_EXPIRED,
    COMMAND_NOT_SUPPORTED,
    ADDRESSS_TYPE_NOT_SUPPORTED,
};

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

class ClientProxyAbstraction: public Socks5RequestProxy, virtual protected EBStreamAbstraction, virtual protected CallbackManager {
    protected:
        virtual void sendServerEnd() = 0;
        virtual void startServerRead() = 0;
        virtual void stopServerRead() = 0;

    public:
        virtual void pushData(ROBuf) = 0;
        virtual void serverEnd() = 0;
        virtual void connectSuccess() = 0;
        virtual void connectFail(ConnectResult) = 0;
};

class ClientProxyAbstraction2: public Socks5RequestProxy {};

class ProxyMultiplexerAbstraction: virtual protected EBStreamAbstraction, virtual protected CallbackManager {
    public:
        using WriteCallbackMM = void(*)(ROBuf buf, int status, void*);
        using ConnectCallback = void (*)(int status, void*);


    public:
        virtual bool    full() = 0;
        virtual uint8_t requireAnId(ClientProxyAbstraction*) = 0;
        virtual uint8_t getConnectionNumbers() = 0;
        virtual bool    connected() = 0;
        virtual bool    uninit() = 0;

        virtual void write(uint8_t id, ClientProxyAbstraction* obj, ROBuf buf, WriteCallbackMM cb, void* data) = 0;

        virtual void connectToServer(ConnectCallback cb, void* data) = 0;
        virtual void new_connection(uint8_t id, ClientProxyAbstraction*, const std::string& addr, uint16_t port, int timeout_ms) = 0;
        virtual void remove_clientConnection(uint8_t, ClientProxyAbstraction*) = 0;

        virtual void sendStartConnectionRead(uint8_t id) = 0;
        virtual void sendStopConnectionRead (uint8_t id) = 0;
        virtual void connectionEnd(uint8_t id, ClientProxyAbstraction* obj) = 0;

        virtual void close() = 0;
};

class ProxyMultiplexerAbstraction2:  protected KProxyMultiplexerStreamProvider {
    public:
        using ConnectCallback = void (*)(int status, void*);


    public:
        virtual bool    full() = 0;
        virtual uint8_t getConnectionNumbers() = 0;
        virtual bool    connected() = 0;
        virtual bool    uninit() = 0;

        virtual void connectToServer(ConnectCallback cb, void* data) = 0;
        virtual void remove_clientConnection(ClientProxyAbstraction2*) = 0;

        virtual void close() = 0;
};

class Server;
class ConnectionProxy;
class RelayConnection;
class ClientConnection;

NS_PROXY_CLIENT_END
