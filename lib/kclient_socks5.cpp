#include "../include/kclient_socks5.h"
#include "../include/callback_data.h"


#define DEBUG(all...) __logger->debug(all)


NS_PROXY_CLIENT_START

/** @calss Socks5Auth 
 * hold a session to complete socks5 method select, user authentication, request */

/** constructor of Socks5Auth */
Socks5Auth::Socks5Auth(Server* server, std::shared_ptr<ClientConfig> config) //{
{
    DEBUG("call %s: new socks5 authentication session", FUNCNAME);
    this->mp_server = server;

    this->m_state = SOCKS5_INIT;
    this->m_config = config;

    this->m_remain = ROBuf();

    this->m_servername = "";
    this->m_port = 80;
} //}

/** recieve the socks5 request, forward this message to Server try to connect the request service */
void Socks5Auth::try_to_build_connection() //{
{
    DEBUG("call %s: try to build a connection to server", FUNCNAME);
    assert(this->m_state == SOCKS5_FINISH);
    this->mp_server->dispatchSocks5(this->m_servername, this->m_port, this);
} //}
/** transfer tcp connection to Server */
void Socks5Auth::return_to_server() //{ 
{
    DEBUG("call %s", FUNCNAME);
    this->stop_read();
    this->mp_server->socks5Transfer(this);
} //}
/** something wrong has happend inform Server to deallocate memory */
static void dummy_shutdown_callback(int status, void* data) {}
void Socks5Auth::close_this_with_error() //{
{
    DEBUG("call %s", FUNCNAME);
    this->m_state = SOCKS5_ERROR;
    this->shutdown(dummy_shutdown_callback, nullptr);
    auto maybe_proxy = this->mp_server->getSock5ProxyObject(this);
    this->close();
    if(maybe_proxy != nullptr) maybe_proxy->close();
} //}

/** implement pure virtual method */
void Socks5Auth::read_callback(ROBuf buf, int status) //{
{
    if(status < 0) {
        this->close_this_with_error();
        return;
    }

    this->dispatch_data(buf);
} //}
void Socks5Auth::end_signal() //{
{
    this->close_this_with_error();
} //}

/** dispatch data base on current state */
void Socks5Auth::dispatch_data(ROBuf buf) //{
{
    DEBUG("call %s = (buf.size()=%d)", FUNCNAME, buf.size());
    switch (this->m_state) {
        case SOCKS5_INIT: {
            auto x = parse_client_hello(this->m_remain, buf);
            bool finished;
            __client_selection_msg msg;
            ROBuf remain;
            std::tie(finished, msg, remain) = x;
            this->m_remain = remain;
            if(finished) {
                if(msg.m_version != 0x5) { // inform client TODO
                    return this->close_this_with_error();
                }
                socks5_authentication_method method = SOCKS5_AUTH_NO_ACCEPTABLE;
                for(auto& i: msg.m_methods) {
                    if(method == SOCKS5_AUTH_NO_ACCEPTABLE && 
                            i == SOCKS5_AUTH_NO_REQUIRED && // FIXME
                            this->m_config->Policy().m_method == SOCKS5_NO_REQUIRED)
                        method = (socks5_authentication_method)i;
                    if(i == SOCKS5_AUTH_USERNAME_PASSWORD) 
                        method = (socks5_authentication_method)i;
                }
                this->m_state = SOCKS5_ID;
                if(method == SOCKS5_AUTH_NO_REQUIRED) this->m_state = SOCKS5_METHOD;
                this->__send_selection_method(method);
            }
            break;}
        case SOCKS5_ID: { // without debug, because chrome socks5 client dones't support username and password
            auto x = parse_username_authentication(this->m_remain, buf);
            bool finished;
            __socks5_username_password msg;
            ROBuf buf;
            std::tie(finished, msg, buf) = x;
            this->m_remain = buf;
            if(finished) {
                if(msg.m_version != 0x5) {
                    // TODO inform error
                    this->close_this_with_error();
                    break;
                }
                uint8_t status = -1;
                if(this->m_config->validateUser(msg.m_username, msg.m_password)) {
                    status = 0;
                    this->m_state = SOCKS5_METHOD;
                }
                this->__send_auth_status(status);
            }
            break;
        }
        case SOCKS5_METHOD: {
            auto x = parse_client_request(this->m_remain, buf);
            bool finished, error;
            __client_request_msg msg;
            ROBuf remain;
            std::tie(finished, msg, remain, error) = x;
            this->m_remain = remain;
            if(error) {
                this->close_this_with_error();
                break;
            }
            if(finished) {
                if(msg.m_version  != 0x5 ||
                   msg.m_command != SOCKS5_CMD_CONNECT ||
                   (msg.m_addr_type != SOCKS5_ADDR_IPV4 && msg.m_addr_type != SOCKS5_ADDR_DOMAIN)) {
                    this->close_this_with_error();
                    break;
                }
                this->m_servername = msg.m_addr;
                this->m_port = msg.m_port;
                this->m_state = SOCKS5_FINISH;
                this->try_to_build_connection(); // TODO
            }
            break;
        }
        case SOCKS5_FINISH:
        case SOCKS5_ERROR:
            assert(false && "bug");
            break;
    }
} //}

/** send hello to socks5 client */
void Socks5Auth::__send_selection_method(socks5_authentication_method method) //{
{
    DEBUG("call %s: send selection mothod: %d", FUNCNAME, (uint8_t)method);
    __server_selection_msg* msg = (decltype(msg))malloc(sizeof(__server_selection_msg));
    msg->m_version = 0x5;
    msg->m_method = method;
    ROBuf buf((char*)msg, sizeof(__server_selection_msg), 0, free);

    auto ptr = new CBD::Socks5Auth$__send_selection_method$_write(this);
    this->add_callback(ptr);

    this->_write(buf, write_callback_hello, ptr);
} //}
/** [static] */
void Socks5Auth::write_callback_hello(ROBuf buf, int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    CBD::Socks5Auth$__send_selection_method$_write* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CBD::CBase*>(data));
    assert(msg);
    Socks5Auth* _this = msg->_this;
    bool run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0)
        _this->close_this_with_error();
} //}

/** send authentication result */
void Socks5Auth::__send_auth_status(uint8_t status) //{
{
    DEBUG("call %s: send authenticate status: %d", FUNCNAME, status);
    __socks5_user_authentication_reply* msg = (__socks5_user_authentication_reply*)malloc(sizeof(__socks5_user_authentication_reply));
    msg->m_version = 0x5;
    msg->m_status = status;
    ROBuf buf((char*)msg, sizeof(*msg), 0, free);

    auto ptr = new CBD::Socks5Auth$__send_auth_status$_write(this);
    this->add_callback(ptr);

    this->_write(buf, write_callback_id, ptr);
} //}
/** [static] */
void Socks5Auth::write_callback_id(ROBuf buf, int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    CBD::Socks5Auth$__send_auth_status$_write* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CBD::CBase*>(data));
    assert(msg);
    Socks5Auth* _this = msg->_this;
    bool run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0)
        _this->close_this_with_error();
} //}

/** send reply */
void Socks5Auth::__send_reply(uint8_t reply) //{
{
    DEBUG("call %s, status: %d, remain_size: %d", FUNCNAME, reply, this->m_remain.size());
    __server_reply_msg msg;
    msg.m_version = 0x5;
    msg.m_reply = (socks5_reply_type)reply;
    msg.m_reserved = 0;
    msg.m_addr_type = SOCKS5_ADDR_IPV4;
    uint32_t ipv4addr;
    char* bufx = nullptr;
    size_t size = 0;
    if(str_to_ip4(this->m_servername.c_str(), &ipv4addr)) {
        size = 10;
        bufx = (char*)malloc(size);
        memcpy(bufx, &msg, 4);
        *(uint32_t*)(bufx + 4) = ipv4addr;
        *(uint16_t*)(bufx + 8) = this->m_port; // FIXME
    } else {
        size = this->m_servername.length() + 7;
        bufx = (char*)malloc(size);
        msg.m_addr_type = SOCKS5_ADDR_DOMAIN;
        memcpy(bufx, &msg, 4);
        *(bufx + 4) = this->m_servername.size();
        memcpy(bufx + 5, this->m_servername.c_str(), this->m_servername.size());
        *(uint16_t*)(bufx + (size - 2)) = this->m_port; // FIXME
    }
    ROBuf buf(bufx, size, 0, free);

    auto ptr = new CBD::Socks5Auth$__send_reply$_write(this, reply);
    this->add_callback(ptr);

    this->_write(buf, write_callback_reply, ptr);
} //}
/** [static] */
void Socks5Auth::write_callback_reply(ROBuf buf, int status, void* data) //{
{
    DEBUG("call %s", FUNCNAME);
    CBD::Socks5Auth$__send_reply$_write* msg = 
        dynamic_cast<decltype(msg)>(static_cast<CBD::CBase*>(data));
    assert(msg);
    Socks5Auth* _this = msg->_this;
    uint8_t reply = msg->_reply;
    bool run = msg->CanRun();
    delete msg;

    if(!run) return;
    _this->remove_callback(msg);

    if(status < 0 || _this->m_remain.size() != 0 || reply != SOCKS5_REPLY_SUCCEEDED)
        _this->close_this_with_error();
    else 
        _this->return_to_server(); 
} //}

void Socks5Auth::netAccept() //{
{
    DEBUG("call %s", FUNCNAME);
    this->__send_reply(SOCKS5_REPLY_SUCCEEDED);
} //}
void Socks5Auth::netReject() //{
{
    DEBUG("call %s", FUNCNAME);
    this->__send_reply(SOCKS5_REPLY_CONNECTION_REFUSED); // TODO
} //}

void Socks5Auth::start() //{
{
    this->start_read();
} //}
void* Socks5Auth::transferStream() //{
{
    return this->transfer();
} //}

/** wrapper of @close_this_with_error() */
void Socks5Auth::close() //{
{
    DEBUG("call %s", FUNCNAME);
    this->mp_server->remove_socks5(this);
} //}

Socks5Auth::~Socks5Auth() {}

NS_PROXY_CLIENT_END

