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
 *       |   8      |     8      |    8         | [   16/32  ]    | LENGTH bytes |
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

#define OPCODE_INFO(FUNC) \
    FUNC(PACKET_OP_WRITE,             "write back") \
    FUNC(PACKET_OP_CREATE_CONNECTION, "request a new connection") \
    FUNC(PACKET_OP_ACCEPT_CONNECTION, "accept request of new connection") \
    FUNC(PACKET_OP_REJECT_CONNECTION, "reject request of new connection") \
    FUNC(PACKET_OP_CLOSE_CONNECTION,  "close a connection and release the id") \
    FUNC(PACKET_OP_END_CONNECTION,    "equivalent to finish flag of tcp") \
    FUNC(PACKET_OP_START_READ,        "inform the other end start writing") \
    FUNC(PACKET_OP_STOP_READ,         "inform the other end stop writing") \
    FUNC(PACKET_OP_RESERVED,          "reserved opcode")


#define OPCODE_ENUM(op, desc) op, 
enum PACKET_OPCODE: uint8_t {
    OPCODE_INFO(OPCODE_ENUM)
};
#undef OPCODE_ENUM

const char* packet_opcode_description(PACKET_OPCODE op);
const char* packet_opcode_name(PACKET_OPCODE op);


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


/** @return <noerror, finish, frame, remain, opcode, id> */
std::tuple<bool, bool, ROBuf, ROBuf, PACKET_OPCODE, ConnectionId> decode_packet(ROBuf remain, ROBuf income);
/** @return <noerror, <frame, opcode, id>, remain> */
std::tuple<bool, std::vector<std::tuple<ROBuf, PACKET_OPCODE, uint8_t>>, ROBuf> decode_all_packet(ROBuf remain, ROBuf income);

ROBuf encode_packet_header(PACKET_OPCODE op, ConnectionId id, size_t len);
ROBuf encode_packet(PACKET_OPCODE op, ConnectionId id, size_t len, void* buf);
ROBuf encode_packet(PACKET_OPCODE op, ConnectionId id, ROBuf buf);

