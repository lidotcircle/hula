#pragma once

#include "events.h"
#include "utils.h"
#include "kpacket.h"
#include "kserver_config.h"
#include "config.h"
#include "object_manager.h"

#define DEFAULT_BACKLOG 100

/**                           DESIGN OVERVIEW                                     //{
 *
 *   CLIENT SIDE
 *                                                                             
 *                               OTHERS APPLICATIONS
 * --------------------------------------------------------------------------------------
 *           |               |                                     |            
 *           |               |                                     |            
 *           |               |                                     |            
 *           v               v     INCOME SOCKS5 PROXY             v            
 *           -------------------------------------------------------                                                                 
 *           ~                    |           |         |                      
 *           ~                    v           v         v                      
 *           ~             -----------------------------------
 *           ~             |               SOCKS5 PROXY      |
 *     RELAY ~             |    SERVER     Listen AT ...     |
 *           ~             |                                 |
 *           ~             ----------------------------------
 *           ~                    |                        |          ...
 *           ~                    |                        |          ...
 *     ----------               ----------------------       ----------------------
 *     | Client |    SETOF      |                    |       |                    |
 *     | Proxy  | <------------ |   ConnectionProxy  |       |   ConnectionProxy  | ....
 *     |        |               |                    |       |                    |
 *     | -TCP   |     --------->|                    |       |                    |
 *     ----------     |         ----------------------       ----------------------
 *                    |          |                   |                         
 *                    |          | TCP               |            ............ 
 *            SSL/TSL |          | REQUEST           |            ............ 
 *                    |          |                   |            ............ 
 *        Connection  |          |                   |                         
 *        Multiplexer |          |                   |                         
 *                    |          |                   |                         
 *   _________________|__________|___________________|_____________________________  NETWORK
 *                    |          |                   |                         
 *                    |          |                   |                         
 *                    |          |                   |                         
 *   SERVER SIDE      |          |                   |                                    
 *                    |          v                   v                         
 *                    |    -----------------------------------                                                                   
 *                    |    |                                 |                                                     
 *                    |    |    SERVER     Listen AT ...     |                                                           
 *                    |    |                                 |                                                     
 *                    |    -----------------------------------
 *                    |           |            |          ......                                  
 *                    v           |            |          ......                                  
 *         ----------------------------       ----------------------------           -----------------
 *         |                          |       |                          |   SETOF   | ServerTo      |
 *         |   ClientConnectionProxy  |       |   ClientConnectionProxy  |  -------> | NetConnection |
 *         |                          |       |                          |           | -TCP          |
 *         ----------------------------       ----------------------------           -----------------
 *                                                                                       ^
 *                                                                                       |
 *               .                                              .                        | PROXY TRAFFIC
 *               .                                              .                        |
 *               .                                              .                        v
 * --------------------------------------------------------------------------------------------------- INTERNET
 *                                                                             
 *///}

#define NS_PROXY_SERVER_START namespace KProxyServer {
#define NS_PROXY_SERVER_END   }

NS_PROXY_SERVER_START

/* forward declaration */
class Server;
class ClientConnectionProxy;
class ServerToNetConnection;

NS_PROXY_SERVER_END
