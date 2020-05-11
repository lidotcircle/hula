#include "../include/kpacket.h"
#include "../include/utils.h"

#include <stdlib.h>
#include <string.h>

#include <vector>

#define __MAX(a, b) a > b ? a : b
#define __MIN(a, b) a > b ? b : a


/**
 * @param {ROBuf*} remain unfinished buffer
 * @param {ROBuf*} income latest recieved buffer
 * @return if get<0>(return) is nullptr, frame doesn't complete
 * @exception if income equals nullptr then raise error
 */
std::tuple<ROBuf*, ROBuf*, PacketOp, ConnectionId> decode_packet(ROBuf* remain, ROBuf* income) //{
{
    xassert(income != nullptr);

    PacketHeader header;
    memset(&header, 0, sizeof(PacketHeader));

    uint32_t len = 0;
    size_t i = 0;

    if(remain != nullptr)
        i = remain->size();
    if(i > sizeof(PacketHeader))
        i = sizeof(PacketHeader);
    if(i > 0)
        memcpy(&header, remain->base(), i);
    if(i < sizeof(PacketHeader))
        memcpy((char*)&header + i, income->base(), __MIN(sizeof(PacketHeader) - i, income->size()));

    size_t header_size = 0;
    switch(header.length) {
        case 0xFE:
            header_size = offsetof(PacketHeader, extend_length.e32);
            len = ntohs(header.extend_length.e16);
            break;
        case 0xFF:
            header_size = sizeof(PacketHeader);
            len = ntohl(header.extend_length.e32);
            break;
        default:
            header_size = offsetof(PacketHeader, extend_length.e16);
            len = header.length;
            break;
    }

    PacketOp op     = (PacketOp)header.opcode;
    ConnectionId id = header.id;

    xassert(len != 0); // TODO

    if(len + header_size > (remain == nullptr ? 0 : remain->size()) + income->size()) {
        if(remain != nullptr) {
            return std::make_tuple(new ROBuf(*remain + *income), nullptr, op, id);
        } else {
            income->ref();
            return std::make_tuple(new ROBuf(*income), nullptr, op, id);
        }
    } else {
        ROBuf* merge;
        if(remain != nullptr) {
            merge = new ROBuf(*remain + *income);
        } else {
            merge = new ROBuf(*income);
            merge->ref();
        }
        ROBuf* frame = new ROBuf(merge, len, header_size);
        merge->unref();
        if(merge->size() == len + header_size)
            return std::make_tuple(nullptr, frame, op, id);
        ROBuf* remain = new ROBuf(merge, merge->size() - len - header_size, len + header_size);
        return std::make_tuple(frame, remain, op, id);
    }
} //}


/**
 * @see decode_packet()
 */
std::tuple<std::vector<std::tuple<ROBuf*, PacketOp, uint8_t>>, ROBuf*> decode_all_packet(ROBuf* remain, ROBuf* income) //{
{
    xassert(income != nullptr);
    ROBuf *x_remain = nullptr, *x_income = new ROBuf(*income);
    x_income->ref();
    if(remain != nullptr) {
        x_remain = new ROBuf(*remain);
        x_remain->ref();
    }

    std::vector<std::tuple<ROBuf*, PacketOp, uint8_t>> ret;

    while(true) {
        ROBuf *a, *b;
        PacketOp op;
        uint8_t id;
        std::tie(a, b, op, id) = decode_packet(x_remain, x_income);
        delete x_income;
        delete x_remain;
        if(a != nullptr) ret.push_back(std::make_tuple(a, op, id));
        x_income = b;
        x_remain = nullptr;
        if(a == nullptr) {
            x_remain = b;
            break;
        }
    }

    return std::make_tuple(ret, x_remain);
} //}


/** create packet header buffer */
ROBuf encode_packet_header(PacketOp op, ConnectionId id, size_t len) //{
{
    xassert(op < 1 << 2 && id < 1 << 6);
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
    memcpy(ret.base(), &header, header_size);
    return ret;
} //}


/** create packet */
ROBuf encode_packet(PacketOp op, ConnectionId id, size_t len, void* buf) //{
{
    ROBuf header = encode_packet_header(op, id, len);
    ROBuf payload = ROBuf(buf, len);
    ROBuf ret = header + payload;
    header.unref();
    payload.unref();
    return ret;
} //}

