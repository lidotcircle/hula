#pragma once

#include "file.h"
#include "file_libuv.h"
#include "http.h"
#include "http_file_server_config.h"
#include "stream.h"

#include <memory>
#include <set>

#include <evtls/help_class.h>
using namespace evtls;


/** events */
// @dead the lisener should delete this object
class HttpFileServer: virtual protected EBStreamAbstraction, public StoreFetchPointer, virtual public EventEmitter
{
    public:
        struct FileServerRequestInfo: public HttpRequest::Info, public CallbackManager {
            FileAbstraction* file;
            Http*            http;
            HttpFileServer*  _this;
            HttpRequest*     request;
            int start_pos = -1;
            int end_pos = -1;
            int cur_pos = -1;
            inline ~FileServerRequestInfo() {if(file) delete file;}
        };
        struct UpgradeExtraData {
            inline virtual ~UpgradeExtraData() {}
        };

        struct UpgradeRequest {
            virtual void reject() = 0;
            virtual UNST accept() = 0;

            virtual std::string value(const std::string& field) = 0;
            virtual std::string url() = 0;
            virtual ROBuf       data() = 0;

            virtual void setHeader(const std::string& field, const std::string& value) = 0;
        };

        using UpgradeHandler   = void (*)(UpgradeRequest* upgrade, UpgradeExtraData* data);
        using WebsocketHandler = UpgradeHandler;


    private:
        struct UpgradeRequestIMPL: public UpgradeRequest {
            private:
                HttpRequest* m_request;


            public:
                UpgradeRequestIMPL(HttpRequest* request);
                void reject() override;
                UNST accept() override;

                std::string value(const std::string& field) override;
                std::string url() override;
                ROBuf       data() override;

                void setHeader(const std::string& field, const std::string& value) override;
        };

        std::shared_ptr<HttpFileServerConfig> m_config;
        std::set<Http*> m_sessions;

        UpgradeHandler    m_upgrade_handler;
        WebsocketHandler  m_ws_handler;
        UpgradeExtraData* m_upgrade_data;

        void ws_upgrade_preprocess(HttpRequest* request, UpgradeRequest* rr);

        void register_listeners(Http* session);

        static void upgrade_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void upgraded_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void request_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void error_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base*);
        static void drain_listener(EventEmitter* obj, const std::string& eventname, EventArgs::Base*);

        void FinishSession(Http* session);


    protected:
        virtual Http*            createHttpSession(UNST con) = 0;
        virtual FileAbstraction* createFile(const std::string& filename) = 0;
        void on_connection(UNST con) override;


    public:
        HttpFileServer(std::shared_ptr<HttpFileServerConfig> config);

        HttpFileServer(const HttpFileServer&) = delete;
        HttpFileServer(HttpFileServer&&) = delete;
        HttpFileServer& operator=(const HttpFileServer&) = delete;
        HttpFileServer& operator=(HttpFileServer&&) = delete;

        void EmitAnConnection(UNST con, ROBuf firstPacket);

        void bind();
        using EBStreamAbstraction::bind;
        using EBStreamAbstraction::bind_ipv4;
        using EBStreamAbstraction::bind_ipv6;
        using EBStreamAbstraction::listen;

        using EBStreamAbstraction::newUnderlyStream;
        using EBStreamAbstraction::releaseUnderlyStream;

        void SetUpgradeHandler(UpgradeHandler h);
        void SetWSHandler(UpgradeHandler h);
        void SetUpgradeData(UpgradeExtraData* data);

        void close();
        ~HttpFileServer();
};

