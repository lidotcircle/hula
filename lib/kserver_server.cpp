#include "../include/kserver_server.h"
#include "../include/logger.h"
#include "../include/utils.h"
#include "../include/config.h"
#include "../include/config_file.h"
#include "../include/ObjectFactory.hpp"


#include <stdlib.h>
#include <assert.h>

#include <tuple>


#define DEBUG(all...) __logger->debug(all)


NS_PROXY_SERVER_START

/** connection callback function */
void Server::on_connection(void* connection) //{
{
    DEBUG("call %s", FUNCNAME);
    if(connection == nullptr) {
        __logger->warn("new connection error");
        return;
    }

    ConnectionProxyAbstraction* newproxy = Factory::createConnectionProxy(this, connection);
    this->m_connection_list.insert(newproxy);
    newproxy->start();
    return;
} //}

/** delete ConnectionProxyAbstraction object */
void Server::remove_proxy(ConnectionProxyAbstraction* p) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->m_connection_list.find(p) != this->m_connection_list.end());
    this->m_connection_list.erase(this->m_connection_list.find(p));
    delete p;
} //}

/** implement an abstract method */
void Server::read_callback(ROBuf buf, int status) //{
{
    assert(false && "bad");
} //}

/** constructor of Server*/
Server::Server(std::shared_ptr<ServerConfig> config): m_connection_list() //{
{
    DEBUG("call %s", FUNCNAME);
    this->m_config = config;
    this->bind_addr = config->BindAddr();
    this->bind_port = config->BindPort();
} //}

/** functions related with listen */
int Server::trylisten() //{ 
{
    DEBUG("call %s", FUNCNAME);
    sockaddr_in addr;

    uint32_t network_order_addr = k_htonl(this->bind_addr);

    ip4_addr(ip4_to_str(network_order_addr), this->bind_port, &addr);
    if(!this->bind((struct sockaddr*)&addr)) {
        logger->error("bind error %s:%d", ip4_to_str(network_order_addr), this->bind_port);
        return -1;
    }
    if(!this->listen()) {
        logger->error("listen error %s:%d", ip4_to_str(network_order_addr), this->bind_port);
        return -1;
    }
    logger->debug("listen at %s:%d", ip4_to_str(network_order_addr), this->bind_port);
    return 0;
} //}

/** release objects */
void Server::close() //{
{
    DEBUG("call %s", FUNCNAME);
    auto connection_list_copy = this->m_connection_list;
    for(auto&x: connection_list_copy)
        x->close();

    this->release();
    this->m_config.reset();
    return;
} //}

Server::~Server() {}

NS_PROXY_SERVER_END

