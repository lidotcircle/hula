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
std::tuple<bool, ROBuf, ROBuf, PacketOp, ConnectionId> decode_packet(const ROBuf remain, const ROBuf income) //{
{
    xassert(!income.empty());

    PacketHeader header;
    memset(&header, 0, sizeof(PacketHeader));

    uint32_t len = 0;
    size_t i = remain.size();

    if(i > sizeof(PacketHeader))
        i = sizeof(PacketHeader);
    if(i > 0)
        memcpy(&header, remain.base(), i);
    if(i < sizeof(PacketHeader) || income.size() > 0)
        memcpy((char*)&header + i, income.base(), __MIN(sizeof(PacketHeader) - i, income.size()));

    size_t header_size = 0;
    switch(header.length) {
        case 0xFE:
            header_size = 4;
            len = k_ntohs(header.extend_length.e16);
            break;
        case 0xFF:
            header_size = 6;
            len = k_ntohl(header.extend_length.e32);
            break;
        default:
            header_size = 2;
            len = header.length;
            break;
    }

    Logger::logger->debug("len: %d, header_size: %d", len, header_size);

    PacketOp op     = (PacketOp)header.opcode;
    ConnectionId id = header.id;

    if(remain.size() + income.size() < header_size)
        return std::make_tuple(true, ROBuf(), remain + income, op, id);

    if(len == 0)
        return std::make_tuple(false, ROBuf(), remain + income, op, id);

    if(len + header_size > remain.size() + income.size()) {
        if(!remain.empty()) {
            return std::make_tuple(true, ROBuf(), remain + income, op, id);
        } else {
            return std::make_tuple(true, ROBuf(), income, op, id);
        }
    } else {
        ROBuf merge;
        if(!remain.empty()) {
            merge = remain + income;
        } else {
            merge = income;
        }
        ROBuf frame = ROBuf(merge, len, header_size);
        if(merge.size() == len + header_size)
            return std::make_tuple(true, frame, ROBuf(), op, id);
        ROBuf remain = ROBuf(merge, merge.size() - len - header_size, len + header_size);
        return std::make_tuple(true, frame, remain, op, id);
    }
} //}


/**
 * @see decode_packet()
 */
std::tuple<bool, std::vector<std::tuple<ROBuf, PacketOp, uint8_t>>, ROBuf> decode_all_packet(const ROBuf remain, const ROBuf income) //{
{
    xassert(!income.empty());

    ROBuf x_remain;
    ROBuf x_income(income);
    if(!remain.empty())
        x_remain = remain;

    std::vector<std::tuple<ROBuf, PacketOp, uint8_t>> ret;

    while(true) {
        bool noerror;
        ROBuf a, b;
        PacketOp op;
        uint8_t id;
        std::tie(noerror, a, b, op, id) = decode_packet(x_remain, x_income);
        if(noerror == false)
            return std::make_tuple(false, ret, b);
        if(!a.empty()) ret.push_back(std::make_tuple(a, op, id));
        x_income = b;
        x_remain = ROBuf();
        if(a.empty()) {
            x_remain = b;
            break;
        }
    }

    return std::make_tuple(true, ret, x_remain);
} //}


/** create packet header buffer */
ROBuf encode_packet_header(PacketOp op, ConnectionId id, size_t len) //{
{
    xassert(op < 1 << 4 && id < 1 << 6);
    xassert(len < 1l << 32);
    size_t header_size = 0;
    void* buf = nullptr;

    PacketHeader header;
    header.opcode = op;
    header.id = id;

    if(len < 0xFE) {
        header_size = offsetof(PacketHeader, extend_length.e16);
        header.length = len;
    } else if(len > 2 << 16) {
        header_size = offsetof(PacketHeader, extend_length.e32);
        header.length = 0xFE;
        header.extend_length.e16 = htons(len);
    } else  {
        header_size = sizeof(PacketHeader);
        header.length = 0xFF;
        header.extend_length.e32 = htonl(len);
    }

    ROBuf ret(header_size);
    memcpy(ret.__base(), &header, header_size);
    return ret;
} //}


/** create packet */
ROBuf encode_packet(PacketOp op, ConnectionId id, size_t len, void* buf) //{
{
    ROBuf header = encode_packet_header(op, id, len);
    ROBuf payload = ROBuf(buf, len);
    ROBuf ret = header + payload;
    return ret;
} //}

ROBuf encode_packet(PacketOp op, ConnectionId id, ROBuf buf) //{
{
    ROBuf header = encode_packet_header(op, id, buf.size());
    return header + buf;
} //}

