#include "../include/kserver.h"
#include "../include/kserver_multiplexer.h"
#include "../include/callback_data.h"
#include "../include/ObjectFactory.h"
#include "../include/config.h"


#define DEBUG(all...) __logger->debug(all)


NS_PROXY_SERVER_START

struct ClientConnectionProxy_callback_state: public CallbackPointer {
    ClientConnectionProxy* _this;
    ClientConnectionProxy_callback_state(decltype(_this) _this): _this(_this) {}
};

/** constructor of ClientConnectionProxy */
ClientConnectionProxy::ClientConnectionProxy(Server* server): m_remains(), m_relays() //{
{
    DEBUG("call %s", FUNCNAME);
    this->mp_server = server;
    this->in_authentication = true;
} //}

/** implement pure virtual methods */
void ClientConnectionProxy::read_callback(ROBuf buf, int status) //{
{
    DEBUG("call %s", FUNCNAME);

    if(status < 0) {
        this->close();
        return;
    }

    ROBuf allbuf = this->m_remains + buf;
    this->m_remains = ROBuf();

    if(this->in_authentication) {
        this->dispatch_authentication_data(allbuf);
    } else {
        this->prm_read_callback(allbuf);
    }
} //}
static void dummy_shutdown_callback(int status, void*) {}
void ClientConnectionProxy::end_signal() //{
{
    DEBUG("call %s", FUNCNAME);
    this->shutdown(dummy_shutdown_callback, nullptr);
    this->close();
} //}

void ClientConnectionProxy::prm_error_handle() //{
{
    DEBUG("call %s", FUNCNAME);
    this->close();
} //}
void ClientConnectionProxy::prm_write(ROBuf buf, KProxyMultiplexerStreamProvider::WriteCallback cb, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    this->_write(buf, cb, data);
} //}
void ClientConnectionProxy::prm_timeout(KProxyMultiplexerStreamProvider::TimeoutCallback cb, void* data, int ms) //{
{
    DEBUG("call %s", FUNCNAME);
    EBStreamAbstraction* stream_this = static_cast<decltype(stream_this)>(this);
    assert(stream_this->timeout(cb, data, ms));
} //}

using __authentication_write_state = ClientConnectionProxy_callback_state;
void ClientConnectionProxy::dispatch_authentication_data(ROBuf buf) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->in_authentication && "????????");
    if(buf.size() < 2) {
        this->m_remains = buf;
        return;
    }
    uint8_t username_len = buf.base()[0];
    if(buf.size() < username_len + 3) {
        this->m_remains = buf;
        return;
    }
    uint8_t password_len = buf.base()[username_len + 1];
    if(buf.size() < username_len + password_len + 2) {
        this->m_remains = buf;
        return;
    }

    char* username = (char*)malloc(username_len + 1);
    char* password = (char*)malloc(password_len + 1);
    memcpy(username, buf.base() + 1, username_len);
    memcpy(password, buf.base() + 2 + username_len, password_len);
    username[username_len] = '\0';
    password[password_len] = '\0';
    __logger->info("Authentication: [username: %s, password: %s]", username, password);

    bool authenticate_pass = this->mp_server->m_config->validateUser(username, password);

    free(username);
    free(password);

    this->in_authentication = false;
    auto ptr = new ClientConnectionProxy_callback_state(this);
    this->add_callback(ptr);
    if(authenticate_pass) {
        __logger->info("Authentication success");
        this->m_remains = buf.increaseOffset(username_len + password_len + 2);
        this->_write(ROBuf((char*)"\xff\x00", 2), authentication_write_callback, ptr);
    } else {
        __logger->warn("Authentication fail");
        this->_write(ROBuf((char*)"\x00\x00", 2), authentication_write_callback, ptr);
        this->close();
    }
} //}
/** [static] */
void ClientConnectionProxy::authentication_write_callback(ROBuf buf, int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    __authentication_write_state* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CallbackPointer*>(data));
    auto _this = msg->_this;
    auto run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0) {
        _this->close();
        return;
    }
} //}

void ClientConnectionProxy::start() //{
{
    DEBUG("call %s", FUNCNAME);
    this->start_read();
} //}

void ClientConnectionProxy::CreateNewConnection(EBStreamObject* obj, StreamId id, const std::string& addr, uint16_t port) //{
{
    DEBUG("call %s", FUNCNAME);
    auto connection = this->newUnderlyStream();
    ToNetAbstraction* relay = Factory::KProxyServer::createToNet(this, obj, connection, id, addr, port);
    this->m_relays.insert(relay);
    relay->connectToAddr();
} //}

/** delete a conneciton */
void ClientConnectionProxy::remove_connection(ToNetAbstraction* con) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_relays.find(con) != this->m_relays.end());
    this->m_relays.erase(this->m_relays.find(con));
    delete con;
} //}

/** close this object */
void ClientConnectionProxy::close() //{
{
    DEBUG("call %s", FUNCNAME);
    auto relays_copy = this->m_relays;
    for(auto& x: relays_copy)
        x->close();

    this->mp_server->remove_proxy(this);
} //}

NS_PROXY_SERVER_END
