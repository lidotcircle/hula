#pragma once

#include <string>
#include <tuple>
#include <vector>
#include <random>

#include <string.h>

#include "events.h"
#include "robuf.h"
#include "kpacket.h"
#include "utils.h"

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
    TIME_WAIT, 
    CLOSED,    
};

enum WebsocketStatusCode {
    CLOSE_NORMAL = 1000,
    CLOSE_GOING_AWAY,
    CLOSE_PROTOCOL_ERROR,
    CLOSE_UNEXPECT_DATA
};

PACK(
struct WSHeaderPartial {
    uint8_t FIN:1;
    uint8_t RSV1:1;
    uint8_t RSV2:1;
    uint8_t RSV3:1;
    uint8_t OPCODE:4;

    uint8_t MASK:1;
    uint8_t PAYLOAD_LEN:7;
});

template<typename T>
class TCPAbstractConnection //{
{
    public:
        /** #status<0 means error */
        using WriteCallback = void (*)(ROBuf buf, int status);
        using ReadCallback = void(*)(ROBuf buf, int status);

    protected:
        virtual int _write(ROBuf buf, WriteCallback cb) = 0;
        virtual int _close() = 0;
        virtual int _init_with(T* data) = 0;

        virtual void read_callback(ROBuf buf, int status) = 0;
}; //}

/**
 * @event message 
 *     @fires when recieve a message
 *     @param (msg: ROBuf)
 * @event messageText
 *     @fires when recieve a utf8 message
 *     @param (msg: string)
 * @event fragment
 *     @fires recieve a fragment
 *     @param (FIN: boolean, reserved: ReservedBits, opcode: WebsocketOpcode fra: Buffer | string)
 * @event reserve
 *     @fires recieve a fragment whose opcode is reserve
 *     @param (FIN: boolean, reserved: ReservedBits, opcode: WebsocketOpcode fra: Buffer | string)
 * @event error
 *     @fires something wrong has happend, underlying socket error and websocket header error
 *     @param (err: Error)
 * @event ping
 *     @fires recieve ping, the default action is send back a pong
 *     @param (msg: string)
 * @event pong 
 *     @fires recieve pong
 *     @pong (msg: string)
 * @event end
 *     @fires other endpoint send close frame
 *     @param (statusCode: number, reason: Buffer)
 * @event close
 *     @fires underlying tcp socket is closed
 *     @param (clean: boolean) indicates whether websocket is closed cleanly
 */
template<typename T>
class WebSocketCommon: public EventEmitter, public TCPAbstractConnection<T> //{
{
    private:
        WebsocketState m_state;
        bool m_save_fragment;

        struct ExtractReturn {
            bool m_fin;
            uint8_t m_opcode;
            ROBuf m_message;
        };
        struct ExtractReturnSingle: public ExtractReturn {
            bool m_has;
            ROBuf m_remain;
        };

        static ExtractReturnSingle extractFrameFromData(ROBuf buf);
        static std::tuple<std::vector<ExtractReturn>, ROBuf> extractMultiFrameFromData(ROBuf buf);
        static ROBuf formFrame(bool fin, WebsocketOPCode opcode, bool mask, ROBuf message,
                               bool rsv1 = false, bool rsv2 = false, bool rsv3 = false);

        static void write_callback(ROBuf buf, int status);

    public:
        WebSocketCommon(T* underlytcp, bool save_fragment);
        int send(ROBuf buf);
        int sendText(const std::string& reason);
        int ping();
        int pong();
        int close(WebsocketStatusCode statusCode, const std::string& reason);
}; //}

// class WebsocketCommon IMPLEMENTATION //{
template<typename T> /** static */
typename WebSocketCommon<T>::ExtractReturnSingle WebSocketCommon<T>::extractFrameFromData(ROBuf buf) //{
{
    ExtractReturnSingle ret;
    if(buf.size() < sizeof(WSHeaderPartial)) {
        ret.m_has = false;
        return ret;
    }

    WSHeaderPartial* header;
    header = static_cast<decltype(header)>(static_cast<void*>(buf.__base()));
    ret.FIN = (header->FIN == 1);
    ret.opcode = header->OPCODE;

    uint64_t data_offset = sizeof(WSHeaderPartial);
    bool mask = (header->MASK == 1);
    if(mask) data_offset += 4;

    uint8_t len1 = header->PAYLOAD_LEN;
    uint64_t len = 0;
    assert(len1 <= 127);
    if(len1 < 126) {
        len = len1;
    } else if(len1 == 126) {
        uint16_t* uu = static_cast<uint16_t*>(static_cast<void*>(buf.__base() + sizeof(WSHeaderPartial)));
        data_offset += 2;
        len = k_ntohs(*uu);
    } else {
        uint64_t* uu = static_cast<uint64_t*>(static_cast<void*>(buf.__base() + sizeof(WSHeaderPartial)));
        data_offset += 8;
        len = k_ntohll(*uu);
    }

    if(len + data_offset < buf.size()) {
        ret.m_has = false;
        return ret;
    } else {
        ret.m_has = true;
    }

    if(mask) {
        char mask_array[4];
        mask_array[0] = *(buf.base() + data_offset - 4);
        mask_array[1] = *(buf.base() + data_offset - 3);
        mask_array[2] = *(buf.base() + data_offset - 2);
        mask_array[3] = *(buf.base() + data_offset - 1);
        char* payload_start = buf.__base() + data_offset;
        for(size_t i=0; i<len; i++) {
            int j = (i % 4);
            payload_start[i] = mask_array[j] ^ payload_start[i];
        }
    }

    ret.message =  ROBuf(buf, data_offset, len);
    ret.m_remain = ROBuf(buf, data_offset + len, buf.size() - data_offset - len);

    return ret;
} //}
template<typename T> /** static */
std::tuple<std::vector<typename WebSocketCommon<T>::ExtractReturn>, ROBuf> WebSocketCommon<T>::extractMultiFrameFromData(ROBuf buf) //{
{
    std::vector<ExtractReturn> first;
    ROBuf remain = buf;

    ExtractReturnSingle ss;
    {
        ss = extractFrameFromData(remain);
        if(ss.m_has) {
            first.push_back(ss);
            remain = ss.m_remain;
        }
    } while(ss.m_has);

    return std::make_tuple(first, remain);
} //}
template<typename T> /** static */
ROBuf WebSocketCommon<T>::formFrame(bool fin, WebsocketOPCode opcode, bool mask, ROBuf message, 
                                    bool rsv1, bool rsv2, bool rsv3) //{
{
    assert(opcode < (1 << 4));
    size_t buf_size = message.size() + sizeof(WSHeaderPartial);
    if(mask) buf_size += 4;
    if(message.size() >= (1 << 16)) buf_size += 8;
    else if(message.size() >= 126)  buf_size += 2;

    ROBuf ret(buf_size);
    char* base = ret.__base();

    WSHeaderPartial* header = static_cast<decltype(header)>(static_cast<void*>(base));
    header->FIN = fin ? 1 : 0;
    header->RSV1= rsv1 ? 1 : 0;
    header->RSV2= rsv2 ? 1 : 0;
    header->RSV3= rsv3 ? 1 : 0;
    header->OPCODE = opcode;
    header->MASK = mask ? 1 : 0;
    if(message.size() < 126) 
        header->PAYLOAD_LEN = message.size();
    else if(message.size() < (1 << 16)) {
        header->PAYLOAD_LEN = 126;
        uint16_t* uu = static_cast<uint16_t*>(static_cast<void*>(base + sizeof(WSHeaderPartial)));
        *uu = k_htons(message.size());
    } else {
        header->PAYLOAD_LEN = 127;
        uint64_t* uu = static_cast<uint64_t*>(static_cast<void*>(base + sizeof(WSHeaderPartial)));
        *uu = k_htonll(message.size());
    }
    if(mask) {
        std::default_random_engine engine;
        std::uniform_int_distribution<char> distribution(0, 255);
        char* mask_base = base + (buf_size - message.size() - 4);
        mask_base[0] = distribution(engine);
        mask_base[1] = distribution(engine);
        mask_base[2] = distribution(engine);
        mask_base[3] = distribution(engine);
        for(size_t i=0; i<message.size(); i++) {
            int j = (i % 4);
            base[buf_size - message.size() + i] = message.base()[i] ^ mask_base[j];
        }
    } else {
        memcpy(base + buf_size - message.size(), message.base(), message.size());
    }

    return ret;
} //}

template<typename T> /** constructor */
WebSocketCommon<T>::WebSocketCommon(T* underlytcp, bool save_fragment) //{
{
    this->_init_with(underlytcp);
    this->m_save_fragment = save_fragment;
} //}
template<typename T>
int WebSocketCommon<T>::send(ROBuf buf) //{
{
    return this->_write(buf, write_callback); // TODO
} //}
//}

template<typename T>
class WebSocketServer: public WebSocketCommon<T> //{
{
}; //}

template<typename T>
class WebSocketClient: public WebSocketCommon<T> //{
{
}; //}

