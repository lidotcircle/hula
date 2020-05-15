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


enum PacketOp: uint8_t {
    PACKET_OP_REG = 0,
    PACKET_OP_NEW,
    PACKET_OP_CLOSE,
    PACKET_OP_RESERVED
};

typedef uint8_t ConnectionId;

struct PacketHeader {
    uint8_t opcode: 2;
    uint8_t id: 6;
    uint8_t length;
    union {
        uint16_t e16;
        uint32_t e32;
    } extend_length;
};

/** @return <frame, remain, opcode, id> */
std::tuple<bool, ROBuf, ROBuf, PacketOp, ConnectionId> decode_packet(ROBuf remain, ROBuf income);
std::tuple<bool, std::vector<std::tuple<ROBuf, PacketOp, uint8_t>>, ROBuf> decode_all_packet(ROBuf remain, ROBuf income);

ROBuf encode_packet_header(PacketOp op, ConnectionId id, size_t len);
ROBuf encode_packet(PacketOp op, ConnectionId id, size_t len, void* buf);

