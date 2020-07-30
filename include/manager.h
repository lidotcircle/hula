#pragma once


#include <evtls/events.h>
#include <evtls/object_manager.h>

#include "http_file_server.h"
#include "http_file_server_config.h"
#include "websocket.h"

#include <set>
#include <string>
#include <vector>


/** A JSON base RPC provider, communicate with websocket.
 *
 *
 * 1. REQUEST:
 *  The expected message has following format,
 *      {
 *          "ID":    <int>,
 *          "FNAME": <string>,
 *          "ARGS": [<string>]
 *      }
 *  Messages differ with above example will be ignored.
 *
 * 2. RESPONCE:
 *  And this manager should return message with following format,
 *      {
 *          "ID":     <int>,
 *          "ERROR":  <bool>,
 *          "RETURN": <string>
 *      }
 *  if the ERROR non-false, then the RETURN should be error message.
 *
 *
 *  ID should greater than 0, except
 *  (ID = -1) specify response of unknown message
 *
 * 3. INFORM:
 *  Inform an event has happend,
 *      {
 *          "EVENTNAME": <string>
 *          "EVENTARGS": [<string>]
 *      }
 */


#define MAX_WAIT_TIMEOUT (3000)


class ResourceManager
{
    public:
        using UNST = EBStreamAbstraction::UNST;

    private:
        HttpFileServer* mp_httpserver;
        std::set<WebSocketServer*> mp_wsserver;

        static void websocketUpgradeHandler(HttpFileServer::UpgradeRequest* upgrade, HttpFileServer::UpgradeExtraData* data);
        void setup_new_ws(WebSocketServer* ws);
        void clean_ws(WebSocketServer* ws);

        static void ws_message_listener    (EventEmitter* obj, const std::string& eventname, EventArgs::Base* args);
        static void ws_messageText_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* args);
        static void ws_error_listener      (EventEmitter* obj, const std::string& eventname, EventArgs::Base* args);
        static void ws_end_listener        (EventEmitter* obj, const std::string& eventname, EventArgs::Base* args);


    protected:
        virtual HttpFileServer*  createHttpFileServer(const std::string& filename, UNST connection) = 0;
        virtual WebSocketServer* createWSSession     (UNST connection) = 0;

        virtual void Request(WebSocketServer* ws, int id, const std::string& fname, std::vector<std::string> args) = 0;
        void         Response(WebSocketServer* ws, int id, bool error, std::string msg);
        bool         Inform(const std::string& eventname, const std::vector<std::string>& args);

        UNST    NewUNST();

        void post_init(const std::string& filename, UNST connection);


    public:
        ResourceManager();

        ResourceManager(ResourceManager&&) = delete;
        ResourceManager(const ResourceManager&) = delete;
        ResourceManager& operator=(ResourceManager&&) = delete;
        ResourceManager& operator=(const ResourceManager&) = delete;

        void bind();
        void listen();
        virtual void close();

        ~ResourceManager();
};

