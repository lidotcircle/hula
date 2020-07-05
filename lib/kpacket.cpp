#include "../include/kpacket.h"
#include "../include/utils.h"
#include "../include/robuf.h"
#include "../include/config.h"

#include <stdlib.h>
#include <string.h>

#include <vector>

#define __MAX(a, b) a > b ? a : b
#define __MIN(a, b) a > b ? b : a


/**
 * @param {ROBuf} remain unfinished buffer
 * @param {ROBuf} income latest recieved buffer
 * @return if get<0>(return) is false, frame error
 */
std::tuple<bool, bool, ROBuf, ROBuf, PACKET_OPCODE, ConnectionId> decode_packet(const ROBuf remain, const ROBuf income) //{
{
    xassert(!income.empty());

    PACKET_OPCODE op = PACKET_OPCODE::PACKET_OP_RESERVED;
    ConnectionId id  = 0xFF;

    PacketHeader header;
    memset(&header, 0, sizeof(PacketHeader));

    uint32_t len = 0;
    size_t i = remain.size();

    if(i > sizeof(PacketHeader))
        i = sizeof(PacketHeader);
    if(i > 0)
        memcpy(&header, remain.base(), i);
    if(i < sizeof(PacketHeader))
        memcpy((char*)&header + i, income.base(), __MIN(sizeof(PacketHeader) - i, income.size()));

    i += __MIN(sizeof(PacketHeader) - i, income.size());
    if(i < offsetof(PacketHeader, extend_length))
        return std::make_tuple(true, false, ROBuf(), remain + income, op, id);

    size_t header_size = 0;
    switch(header.length) {
        case 0xFE:
            header_size = offsetof(PacketHeader, extend_length) + 2;
            len = k_ntohs(header.extend_length.e16);
            break;
        case 0xFF:
            header_size = offsetof(PacketHeader, extend_length) + 4;
            len = k_ntohl(header.extend_length.e32);
            break;
        default:
            header_size = offsetof(PacketHeader, extend_length);
            len = header.length;
            break;
    }

    if(remain.size() + income.size() < header_size)
        return std::make_tuple(true, false, ROBuf(), remain + income, op, id);

    if((header.length == 0xFE && len < 0xFE) ||
       (header.length == 0XFF && len < (1 << 16))) 
        return std::make_tuple(false, false, ROBuf(), ROBuf(), op, id);

    if(len + header_size > remain.size() + income.size()) {
        return std::make_tuple(true, false, ROBuf(), remain + income, op, id);
    } else {
        op = (PACKET_OPCODE)header.opcode;
        id = header.id;

        ROBuf merge = remain + income;
        ROBuf frame = ROBuf(merge, len, header_size);
        ROBuf remain = ROBuf();
        if(merge.size() > len + header_size)
            remain = ROBuf(merge, merge.size() - len - header_size, len + header_size);
        return std::make_tuple(true, true, frame, remain, op, id);
    }
} //}


/**
 * @see decode_packet()
 */
std::tuple<bool, std::vector<std::tuple<ROBuf, PACKET_OPCODE, uint8_t>>, ROBuf> decode_all_packet(const ROBuf remain, const ROBuf income) //{
{
    xassert(!income.empty());

    ROBuf x_remain;
    ROBuf x_income(income);
    if(!remain.empty())
        x_remain = remain;

    std::vector<std::tuple<ROBuf, PACKET_OPCODE, uint8_t>> ret;

    while(true) {
        bool noerror;
        bool finish;
        ROBuf f, r;
        PACKET_OPCODE op;
        uint8_t id;
        std::tie(noerror, finish, f, r, op, id) = decode_packet(x_remain, x_income);

        if(noerror == false)
            return std::make_tuple(false, ret, x_remain);

        if(finish) ret.push_back(std::make_tuple(f, op, id));
        if(!finish || r.size() == 0) {
            x_remain = r;
            break;
        } else {
            x_remain = ROBuf();
            x_income = r;
        }
    }

    return std::make_tuple(true, ret, x_remain);
} //}


/** create packet header buffer */
ROBuf encode_packet_header(PACKET_OPCODE op, ConnectionId id, size_t len) //{
{
    xassert(op < 1 << 4 && id < 1 << 6);
    xassert(len < 1l << 32);
    size_t header_size = 0;
    void* buf = nullptr;

    PacketHeader header;
    header.opcode = op;
    header.id = id;

    if(len < 0xFE) {
        header_size = offsetof(PacketHeader, extend_length);
        header.length = len;
    } else if(len < (1 << 16)) {
        header_size = offsetof(PacketHeader, extend_length) + 2;
        header.length = 0xFE;
        header.extend_length.e16 = htons(len);
    } else  {
        header_size = offsetof(PacketHeader, extend_length) + 4;
        header.length = 0xFF;
        header.extend_length.e32 = htonl(len);
    }

    ROBuf ret(header_size);
    memcpy(ret.__base(), &header, header_size);
    return ret;
} //}


/** create packet */
ROBuf encode_packet(PACKET_OPCODE op, ConnectionId id, size_t len, void* buf) //{
{
    ROBuf header = encode_packet_header(op, id, len);
    ROBuf payload;
    if(len > 0) payload = ROBuf(buf, len);
    ROBuf ret = header + payload;
    return ret;
} //}

ROBuf encode_packet(PACKET_OPCODE op, ConnectionId id, ROBuf buf) //{
{
    ROBuf header = encode_packet_header(op, id, buf.size());
    return header + buf;
} //}

