#pragma once
#include <stdlib.h>
#include <uv.h>

#include <tuple>
#include <memory>
#include <vector>

#include "utils.h"
#include "robuf.h"

/**               Packet Format                                   //{
 *       -------------------------------------------------------------------------
 *       |  OPCODE  |     ID     |    LENGTH    | [ EXTEND LENGTH | ]  Payload   |
 *       -------------------------------------------------------------------------
 *       |   2      |     6      |    8         | [   16/32  ]    | LENGTH bytes |
 *       -------------------------------------------------------------------------
 *       LENGTH = 0xFE, EXTEND LENGTH is 16 bits
 *       LENGTH = 0xFF, EXTEND LENGTH is 32 bits
 *///}

#ifdef __GNUC__
#define PACK( __Declaration__ ) __Declaration__ __attribute__((__packed__))
#endif

#ifdef _MSC_VER
#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))
#endif


enum PACKET_OPCODE: uint8_t {
    PACKET_OP_REG = 0,
    PACKET_OP_NEW,
    PACKET_OP_CONNECT,
    PACKET_OP_REJECT,
    PACKET_OP_CLOSE,
    PACKET_OP_RESERVED
};

enum NEW_CONNECTION_REPLY: uint8_t {
    SUCCESS = 0,
    SERVER_FAIL,
    GET_DNS_FAIL,
    CONNECT_FAIL
};

typedef uint8_t ConnectionId;


PACK(
struct PacketHeader {
    uint8_t opcode;
    uint8_t id;
    uint8_t length;
    union {
        struct {
            uint16_t e16;
            uint16_t ___;
        };
        uint32_t e32;
    } extend_length;
});


/** @return <noerror, frame, remain, opcode, id> */
std::tuple<bool, ROBuf, ROBuf, PACKET_OPCODE, ConnectionId> decode_packet(ROBuf remain, ROBuf income);
std::tuple<bool, std::vector<std::tuple<ROBuf, PACKET_OPCODE, uint8_t>>, ROBuf> decode_all_packet(ROBuf remain, ROBuf income);

ROBuf encode_packet_header(PACKET_OPCODE op, ConnectionId id, size_t len);
ROBuf encode_packet(PACKET_OPCODE op, ConnectionId id, size_t len, void* buf);
ROBuf encode_packet(PACKET_OPCODE op, ConnectionId id, ROBuf buf);

