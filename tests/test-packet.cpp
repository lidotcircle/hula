#include "../include/kpacket.h"
#include "../include/robuf.h"
#include "../include/utils.h"

#include <assert.h>

void packet_decode_test(ROBuf remain, ROBuf income, int q, int w, int e, int r, bool k = true) //{
{
    std::tuple<bool, ROBuf, ROBuf, uint8_t, uint8_t> m = decode_packet(remain, income);

    bool error;
    ROBuf a, b;
    uint8_t c, d;

    std::tie(error, a, b, c, d) = m;

    Logger::logger->debug("%d, %d, 0x%x, 0x%x", a.size(), b.size(), c, d);
    assert(error == k && "buffer length should be 1");
    assert(a.size() == q && "buffer length should be 1");
    assert(b.size() == w && "remain should be nullptr");
    assert(c == e && "opcode ob11");
    assert(d == r && "id 0b111111");
} //}

void packet_encode_test(PacketOp op, uint8_t id, ROBuf buf) //{
{
    auto x = encode_packet(op, id, buf.size(), buf.__base());
    auto y = decode_packet(ROBuf(), x);
    bool a;
    ROBuf f, r;
    PacketOp op_;
    uint8_t id_;
    std::tie(a, f, r, op_, id_) = y;

    assert(a);
    assert(f.size() == buf.size());
    assert(r.size() == 0);
    assert(op_ == op);
    assert(id_ == id);

    std::cout << "-- pass packet encode test" << std::endl;
} //}

int main() //{
{
    Logger::logger_init_stdout();

    packet_decode_test(ROBuf(), ROBuf((char*)"\xff\xee\01\x33", 4),
            1, 0, 0xff, 0xee);
    packet_decode_test(ROBuf(), ROBuf((char*)"\xff\xee\02\x33\x33", 5), 
            2, 0, 0xff, 0xee);
    packet_decode_test(ROBuf(), ROBuf((char*)"\xff\xee\02\x33\x33\x33", 6), 
            2, 1, 0xff, 0xee);
    packet_decode_test(ROBuf((char*)"\xff\xee", 2), ROBuf((char*)"\02\x33\x33\x33", 4), 
            2, 1, 0xff, 0xee);

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

    packet_encode_test((PacketOp)0x01, 0x00, ROBuf((char*)"xyz", 3));
    packet_encode_test((PacketOp)0x01, 0x0e, ROBuf((char*)"xyzzyzzz", 3));
    packet_encode_test((PacketOp)0x01, 0x00, ROBuf((char*)"xyzyzlliimm", 7));

    return 0;
} //}

