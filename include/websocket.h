#pragma once

#include <string>
#include <tuple>
#include <vector>
#include <random>
#include <exception>

#include <string.h>

#include "events.h"
#include "robuf.h"
#include "kpacket.h"
#include "utils.h"
#include "stream.h"

#define __MIN2(x, y) (x < y ? x : y)
#define __MAX2(x, y) (x > y ? x : y)

#define WS_MAX_FRAGMENT_SIZE (1024 * 1024)
#define WS_MAX_WRITE_BUFFER_SIZE (1024 * 1024)

/** websocket operation code */
enum WebsocketOPCode {
    Continue = 0,
    Text,
    Binary,
    Close = 8,
    Ping,
    Pong
};

/** status of a websocket connection */
enum WebsocketState {
    CONNECTING = 0,
    OPEN,      
    CLOSING,   
//    TIME_WAIT, 
    CLOSED,    
};

enum WebsocketStatusCode {
    CLOSE_NORMAL = 1000,
    CLOSE_GOING_AWAY,
    CLOSE_PROTOCOL_ERROR,
    CLOSE_UNEXPECT_DATA
};

struct WebsocketError: public std::exception {
    std::string m_msg;
    inline WebsocketError(const char* msg): m_msg(msg){}
    inline virtual const char* what() {return this->m_msg.c_str();}
};

PACK(
struct WSHeaderPartial {
    union {
        struct {
            uint8_t OPCODE:4;
            uint8_t RSV3:1;
            uint8_t RSV2:1;
            uint8_t RSV1:1;
            uint8_t FIN:1;
        };
        uint8_t first_byte;
    };

    union {
        struct {
            uint8_t PAYLOAD_LEN:7;
            uint8_t MASK:1;
        };
        uint8_t second_byte;
    };
});

// WS Event ARGS //{
class WebSocketCommon;
struct WSEventArgvBase: public EventArgs::Base {
    WebSocketCommon* _this;
    inline WSEventArgvBase(WebSocketCommon* _this): _this(_this) {}
};
struct WSEventMessage: public WSEventArgvBase {
    ROBuf m_msg;
    inline WSEventMessage(WebSocketCommon* _this, ROBuf buf): WSEventArgvBase(_this), m_msg(buf){}
};
struct WSEventTextMessage: public WSEventArgvBase {
    std::string m_msg;
    inline WSEventTextMessage(WebSocketCommon* _this, const std::string& msg): WSEventArgvBase(_this), m_msg(msg){}
};
struct WSEventFragment: public WSEventArgvBase {
    bool m_fin;
    WebsocketOPCode m_opcode;
    bool m_reserved1, m_reserved2, m_reserved3;
    ROBuf m_buf;
    inline WSEventFragment(WebSocketCommon* _this, bool fin, WebsocketOPCode opcode, ROBuf buf,
                           bool rsv1, bool rsv2, bool rsv3): 
        WSEventArgvBase(_this), m_fin(fin), m_opcode(opcode), m_buf(buf),
        m_reserved1(rsv1), m_reserved2(rsv2), m_reserved3(rsv3) {}
};
struct WSEventError: public WSEventArgvBase {
    WebsocketError m_error;
    inline WSEventError(WebSocketCommon* _this, WebsocketError error): WSEventArgvBase(_this), m_error(error) {}
};
struct WSEventDrain: public WSEventArgvBase {
    inline WSEventDrain(WebSocketCommon* _this): WSEventArgvBase(_this) {}
};
struct WSEventPing: public WSEventArgvBase {
    ROBuf m_msg;
    inline WSEventPing(WebSocketCommon* _this, ROBuf msg): WSEventArgvBase(_this), m_msg(msg) {}
};
struct WSEventPong: public WSEventArgvBase {
    ROBuf m_msg;
    inline WSEventPong(WebSocketCommon* _this, ROBuf msg): WSEventArgvBase(_this), m_msg(msg) {}
};
struct WSEventEnd: public WSEventArgvBase {
    int m_status;
    std::string m_reason;
    inline WSEventEnd(WebSocketCommon* _this, int status, const std::string& str): 
        WSEventArgvBase(_this), m_status(status), m_reason(str) {}
};
struct WSEventClose: public WSEventArgvBase {
    int m_clean;
    inline WSEventClose(WebSocketCommon* _this, bool clean): WSEventArgvBase(_this), m_clean(clean) {}
}; //}
/** <<       event summary           >> //{
 * @event message 
 *     @fires when recieve a message
 *     @param (msg: ROBuf)
 * @event messageText
 *     @fires when recieve a utf8 message
 *     @param (msg: string)
 * @event fragment
 *     @fires recieve a fragment
 *     @param (FIN: boolean, reserved: ReservedBits, opcode: WebsocketOpcode fra: Buffer | string)
 * @event error
 *     @fires something wrong has happend, underlying socket error and websocket header error
 *     @param (err: WebsocketError)
 * @event ping
 *     @fires recieve ping, the default action is send back a pong
 *     @param (msg: ROBuf)
 * @event pong 
 *     @fires recieve pong
 *     @param (msg: ROBuf)
 * @event drain
 *     @fires internal write buffer reach down the threshold
 *     @param ()
 * @event end
 *     @fires other endpoint send close frame
 *     @param (statusCode: number, reason: Buffer)
 * @event close
 *     @fires underlying tcp socket is closed
 *     @param (clean: boolean) indicates whether websocket is closed cleanly
 *///}

class WebSocketCommon: virtual public EBStreamAbstraction //{
{
    private:
        WebsocketState m_state;
        bool m_save_fragment;

        bool m_masked;
        bool m_recieve_end;

        ROBuf m_remain;
        ROBuf m_fragments;
        bool  m_save_binary;

        size_t m_write_buffer_size;
        size_t m_read_buffer_size;

        struct ExtractReturn {
            bool m_fin;
            WebsocketOPCode m_opcode;
            ROBuf m_message;
            bool m_rsv1, m_rsv2, m_rsv3;
        };
        struct ExtractReturnSingle: public ExtractReturn {
            bool m_has;
            ROBuf m_remain;
        };

    public:
        static ExtractReturnSingle extractFrameFromData(ROBuf remain, ROBuf income);
        static std::tuple<std::vector<ExtractReturn>, ROBuf> extractMultiFrameFromData(ROBuf remain, ROBuf income);
        static ROBuf formFrameHeader(bool fin, WebsocketOPCode opcode, bool mask, ROBuf message,
                                     bool rsv1 = false, bool rsv2 = false, bool rsv3 = false);

        static void write_callback(ROBuf buf, int status, void* data);
        int  write_wrapper(ROBuf buf);

    protected:
        void read_callback(ROBuf buf, int status) override;
        void end_signal() override;

        void should_start_write() override;
        void should_stop_write () override;
 

    public:
        WebSocketCommon(bool masked, bool save_fragment);
        int send(ROBuf buf);
        int sendText(const std::string& msg);
        int sendFragment(bool fin, WebsocketOPCode opcode, bool mask, ROBuf message, 
                         bool rsv1 = false, bool rsv2 = false, bool rsv3 = false);
        int ping();
        int pong();
        int end(WebsocketStatusCode statusCode, const std::string& reason);
        void close();
        ~WebSocketCommon();
}; //}

class WebSocketServer: public WebSocketCommon //{
{
    public:
        WebSocketServer(bool save_fragment);
}; //}
class WebSocketClient: public WebSocketCommon //{
{
    public:
        WebSocketClient(bool save_fragment);
}; //}

