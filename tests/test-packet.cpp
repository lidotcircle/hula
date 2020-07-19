#include "../include/kpacket.h"
#include "../include/robuf.h"
#include "../include/utils.h"

#include <assert.h>

void packet_decode_test(ROBuf remain, ROBuf income, int q, int w, int e, int r, bool f = true, bool k = true) //{
{
    auto m = decode_packet(remain, income);

    bool noerror, finish;
    ROBuf a, b;
    uint8_t c, d;

    std::tie(noerror, finish, a, b, c, d) = m;

    assert(noerror == k &&  "packet error");
    assert(a.size() == q && "buffer length");
    assert(b.size() == w && "remain length");
    assert(c == e && "opcode");
    assert(d == r && "id");
} //}

void packet_encode_test(PACKET_OPCODE op, uint8_t id, ROBuf buf) //{
{
    auto x = encode_packet(op, id, buf);
    auto y = decode_packet(ROBuf(), x);
    bool a;
    bool finish;
    ROBuf f, r;
    PACKET_OPCODE op_;
    uint8_t id_;
    std::tie(a, finish, f, r, op_, id_) = y;

    assert(a);
    assert(finish);
    assert(f.size() == buf.size());
    assert(r.size() == 0);
    assert(op_ == op);
    assert(id_ == id);

    std::cout << "-- pass packet encode test" << std::endl;
} //}

int main() //{
{
    packet_decode_test(ROBuf(), ROBuf((char*)"\xff\xee\01\x33", 4),
            1, 0, 0xff, 0xee);
    packet_decode_test(ROBuf(), ROBuf((char*)"\xff\xee\02\x33\x33", 5), 
            2, 0, 0xff, 0xee);
    packet_decode_test(ROBuf(), ROBuf((char*)"\xff\xee\02\x33\x33\x33", 6), 
            2, 1, 0xff, 0xee);
    packet_decode_test(ROBuf((char*)"\xff\xee", 2), ROBuf((char*)"\02\x33\x33\x33", 4), 
            2, 1, 0xff, 0xee);

    packet_decode_test(ROBuf((char*)"\xff\xee", 2), ROBuf((char*)"\x0f\x33\x33\x33", 4), 
            0, 6, PACKET_OPCODE::PACKET_OP_RESERVED, 0xFF, false, true);
    packet_decode_test(ROBuf((char*)"\xff\xee", 2), ROBuf((char*)"\xfe\x00\x03", 3) + ROBuf(0x0f), 
            0, 0, PACKET_OPCODE::PACKET_OP_RESERVED, 0xFF, false, false);


    unsigned char* a = (unsigned char*)malloc(500);
    unsigned char* b = (unsigned char*)malloc(500);
    a[0] = 0xff, a[1] = 0xee, a[2] = 0xfe, a[3] = 0x02, a[4] = 0x00;
    packet_decode_test(ROBuf(a, 500, 0, free), ROBuf(b, 500, 0, free), 
            512, 483, 0xff, 0xee);

    unsigned char* c = (unsigned char*)malloc(50000);
    unsigned char* d = (unsigned char*)malloc(50000);
    c[0] = 0xff, c[1] = 0xee, c[2] = 0xff, c[3] = 0x00, c[4] = 0x01, c[5] = 0x00, c[6] =0x00;
    packet_decode_test(ROBuf(c, 50000, 0, free), ROBuf(d, 50000, 0, free), 
            1 << 16, 100000 - (1 << 16) - 7, 0xff, 0xee);

    packet_encode_test((PACKET_OPCODE)0x01, 0x00, ROBuf());
    packet_encode_test((PACKET_OPCODE)0x01, 0x00, ROBuf((char*)"xyz", 3));
    packet_encode_test((PACKET_OPCODE)0x01, 0x0e, ROBuf((char*)"xyzzyzzz", 3));
    packet_encode_test((PACKET_OPCODE)0x01, 0x00, ROBuf((char*)"xyzyzlliimm", 7));
    packet_encode_test((PACKET_OPCODE)0x01, 0x00, ROBuf(0xff));
    packet_encode_test((PACKET_OPCODE)0x01, 0x00, ROBuf(0xffff));
    packet_encode_test((PACKET_OPCODE)0x01, 0x00, ROBuf(0x1ffff));

    return 0;
} //}

