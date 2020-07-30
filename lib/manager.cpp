#include "../include/manager.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <assert.h>


#define DEBUG(all...) __logger->debug(all)


struct UpgradeExtraData__: public HttpFileServer::UpgradeExtraData {
    ResourceManager* _this;
};

ResourceManager::ResourceManager() //{
{
    DEBUG("call %s", FUNCNAME);
    this->mp_httpserver = nullptr;
} //}

static void dead_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base*) {delete obj;}
void ResourceManager::post_init(const std::string& filename, UNST connection) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->mp_httpserver == nullptr);
    assert(this->mp_wsserver.size() == 0);

    this->mp_httpserver = this->createHttpFileServer(filename, connection);
    assert(this->mp_httpserver != nullptr);

    auto edata = new UpgradeExtraData__();
    edata->_this = this;
    this->mp_httpserver->SetUpgradeData(edata);
    this->mp_httpserver->SetWSHandler(websocketUpgradeHandler);
    this->mp_httpserver->StorePtr(this);

    this->mp_httpserver->on("dead", dead_listener);
} //}
/** [static] */
void ResourceManager::websocketUpgradeHandler(HttpFileServer::UpgradeRequest* upgrade, HttpFileServer::UpgradeExtraData* data) //{
{
    DEBUG("call %s", FUNCNAME);
    UpgradeExtraData__* msg = dynamic_cast<decltype(msg)>(data); assert(msg);
    auto _this = msg->_this;

    auto con = upgrade->accept();
    auto ws = _this->createWSSession(con);

    _this->setup_new_ws(ws);
} //}

void ResourceManager::setup_new_ws(WebSocketServer* ws) //{
{
    DEBUG("call %s", FUNCNAME);
    ws->StorePtr(this);

    ws->on("message", ws_message_listener);
    ws->on("messageText", ws_messageText_listener);
    ws->on("error", ws_error_listener);
    ws->on("end", ws_end_listener);

    assert(this->mp_wsserver.find(ws) == this->mp_wsserver.end());
    this->mp_wsserver.insert(ws);
} //}
void ResourceManager::clean_ws(WebSocketServer* ws) //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->mp_wsserver.find(ws) != this->mp_wsserver.end());
    this->mp_wsserver.erase(this->mp_wsserver.find(ws));
    delete ws;
} //}

#define GETTHIS(ET) \
    WebSocketServer* ws = dynamic_cast<decltype(ws)>(obj); assert(ws); \
    ResourceManager* _this = static_cast<decltype(_this)>(ws->FetchPtr()); assert(_this); \
    ET* argv = dynamic_cast<decltype(argv)>(args); assert(argv)
/** [static] */
void ResourceManager::ws_message_listener    (EventEmitter* obj, const std::string& eventname, EventArgs::Base* args) //{
{
    DEBUG("call %s", FUNCNAME);
    GETTHIS(WSEventMessage);
    _this->Response(ws, -1, true, "bad message, expected a text message with json format");
} //}
void ResourceManager::ws_messageText_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base* args) //{
{
    DEBUG("call %s", FUNCNAME);
    GETTHIS(WSEventTextMessage);
    auto msg = argv->m_msg;

    json request;
    try {
        request = json::parse(msg);
    } catch (nlohmann::detail::parse_error err) {
        _this->Response(ws, -1, true, "bad message, expected message is JSON format with 'ID', 'FNAME', 'ARGS'");
        return;
    }

    if(!request.is_object()) {
        _this->Response(ws, -1, true, "bad message, expected message is JSON format with "
                                      "'ID', 'FNAME', 'ARGS', it's an object");
        return;
    }

    if(request.find("ID") == request.end() || !request["ID"].is_number_integer()) {
        _this->Response(ws, -1, true, "ID field error");
        return;
    }
    int id = request["ID"].get<int>();
    if(id <= 0) {
        _this->Response(ws, -1, true, "the request ID should greate than 1");
        return;
    }

    if(request.find("FNAME") == request.end() || !request["FNAME"].is_string()) {
        _this->Response(ws, -1, true, "FNAME field error");
        return;
    }
    std::string fname = request["FNAME"].get<std::string>();

    std::vector<std::string> rpc_args;
    if(request.find("ARGS") != request.end()) {
        if(!request["ARGS"].is_array()) {
            _this->Response(ws, -1, true, "ARGS field error, should be an array or just miss");
            return;
        } else {
            for(auto& arg: request["ARGS"]) {
                if(!arg.is_number_integer() || !arg.is_boolean() || !arg.is_string()) {
                    _this->Response(ws, -1, true, "ARGS field error, accepted args type is string, bool, int");
                    return;
                }
                rpc_args.push_back(arg.get<std::string>());
            }
        }
    }

    _this->Request(ws, id, fname, rpc_args);
} //}
void ResourceManager::ws_error_listener      (EventEmitter* obj, const std::string& eventname, EventArgs::Base* args) //{
{
    DEBUG("call %s", FUNCNAME);
    GETTHIS(WSEventError);
    _this->clean_ws(ws);
} //}
void ResourceManager::ws_end_listener        (EventEmitter* obj, const std::string& eventname, EventArgs::Base* args) //{
{
    DEBUG("call %s", FUNCNAME);
    GETTHIS(WSEventEnd);
    ws->end(WebsocketStatusCode::CLOSE_NORMAL, "NORMAL CLOSE");
    _this->clean_ws(ws);
} //}
#undef GETTHIS

void ResourceManager::Response(WebSocketServer* ws, int id, bool error, std::string msg) //{
{
    DEBUG("call %s", FUNCNAME);
    if(this->mp_wsserver.find(ws) == this->mp_wsserver.end())
        return;

    json theresult = json::object();
    theresult["ID"] = id;
    theresult["ERROR"] = error;
    theresult["RETURN"]= msg;

    std::string ans = theresult.dump(4);
    ws->sendText(ans);
} //}
bool ResourceManager::Inform(const std::string& eventname, const std::vector<std::string>& args) //{
{
    DEBUG("call %s", FUNCNAME);
    if(this->mp_wsserver.size() == 0)  return false;

    json theresult = json::object();
    theresult["EVENTNAME"] = eventname;
    theresult["ARGS"]= args;

    std::string ans = theresult.dump(4);
    for(auto& ws: this->mp_wsserver)
        ws->sendText(ans);

    return true;
} //}

EBStreamAbstraction::UNST    ResourceManager::NewUNST() //{
{
    DEBUG("call %s", FUNCNAME);
    return this->mp_httpserver->newUnderlyStream();
} //}

void ResourceManager::bind() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->mp_httpserver != nullptr);
    this->mp_httpserver->bind();
} //}
void ResourceManager::listen() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->mp_httpserver != nullptr);
    this->mp_httpserver->listen();
} //}

void ResourceManager::close() //{
{
    DEBUG("call %s", FUNCNAME);
    if(this->mp_httpserver != nullptr) {
        this->mp_httpserver->close();
        this->mp_httpserver = nullptr;
    }

    for(auto& ws: this->mp_wsserver)
        delete ws;
    this->mp_wsserver.clear();
} //}

ResourceManager::~ResourceManager() //{
{
    DEBUG("call %s", FUNCNAME);
    assert(this->mp_httpserver == nullptr);
    assert(this->mp_wsserver.size() == 0);
} //}

