#include "../include/kserver_server2net.h"
#include "../include/ObjectFactory.hpp"
#include "../include/config.h"
#include "../include/ObjectFactory.hpp"
#include "../include/callback_data.h"
#include "../include/utils.h"


#define DEBUG(all...) __logger->debug(all)


NS_PROXY_SERVER_START

ServerToNetConnection::ServerToNetConnection(ClientConnectionProxy* proxy, EBStreamObject* obj, 
                                             void* connection, StreamProvider::StreamId id, 
                                             const std::string& addr, uint16_t port) //{
{
    DEBUG("call %s", FUNCNAME);
    this->m_id = id;
    this->m_addr = addr;
    this->m_port = port;
    this->mp_proxy = proxy;
    this->m_connected = false;

    this->setStreamA(obj);
    EBStreamObject* uvstream = Factory::createUVStreamObject(PROXY_MAX_BUFFER_SIZE, connection);
    this->setStreamB(uvstream);

    this->StreamB()->on("connect", connect_listener);
} //}

/** [static] */
void ServerToNetConnection::connect_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* args) //{
{
    DEBUG("call %s", FUNCNAME);
    EBStreamObject* stream = dynamic_cast<decltype(stream)>(obj);
    assert(stream);
    StreamRelay* relay = static_cast<decltype(relay)>(stream->fetchPtr());
    assert(relay);
    ServerToNetConnection* _this = dynamic_cast<decltype(_this)>(relay);
    assert(_this);
    assert(eventname == "connect");
    _this->m_connected = true;

    _this->mp_proxy->CreateConnectionSuccess(_this->m_id);
    _this->start_relay();
} //}

void ServerToNetConnection::connectToAddr() //{
{
    DEBUG("call %s", FUNCNAME);
    static struct sockaddr_storage addr;
    if(k_inet_pton(AF_INET, this->m_addr.c_str(), &addr)) {;
        struct sockaddr_in* addr_in = (decltype(addr_in))&addr;
        this->StreamB()->connectTo(k_ntohl(addr_in->sin_addr.s_addr), this->m_port);
    } else if (k_inet_pton(AF_INET6, this->m_addr.c_str(), &addr)) {
        struct sockaddr_in6* addr_in6 = (decltype(addr_in6))&addr;
        static uint8_t addrofipv6[16];
        memcpy(addrofipv6, &addr_in6->sin6_addr, sizeof(addrofipv6));
        this->StreamB()->connectTo(addrofipv6, this->m_port);
    } else {
        this->StreamB()->connectTo(this->m_addr, this->m_port);
    }
} //}

void ServerToNetConnection::__close() //{
{
    DEBUG("call %s", FUNCNAME);
    this->close();
} //}

void ServerToNetConnection::close() //{
{
    DEBUG("call %s", FUNCNAME);
    if(!this->m_connected)
        this->mp_proxy->CreateConnectionFail(this->m_id, 0x01);

    this->mp_proxy->remove_connection(this);
} //}

ServerToNetConnection::~ServerToNetConnection() {}


NS_PROXY_SERVER_END
