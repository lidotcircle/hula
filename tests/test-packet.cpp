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

    Logger::logger->debug("%d, %d, %d, %d", a.size(), b.size(), c, d);
    assert(error == k && "buffer length should be 1");
    assert(a.size() == q && "buffer length should be 1");
    assert(b.size() == w && "remain should be nullptr");
    assert(c == e && "opcode ob11");
    assert(d == r && "id 0b111111");
} //}


int main() 
{
    Logger::logger_init_stdout();

    packet_decode_test(ROBuf(), ROBuf((char*)"\xff\01\x33", 3),
            1, 0, 0b11, 0b111111);
    packet_decode_test(ROBuf(), ROBuf((char*)"\xff\02\x33\x33", 4), 
            2, 0, 0b11, 0b111111);
    packet_decode_test(ROBuf(), ROBuf((char*)"\xff\02\x33\x33\x33", 5), 
            2, 1, 0b11, 0b111111);
    packet_decode_test(ROBuf((char*)"\xff", 1), ROBuf((char*)"\02\x33\x33\x33", 4), 
            2, 1, 0b11, 0b111111);

    packet_decode_test(ROBuf((char*)"\xff", 1), ROBuf((char*)"\02\x33\x33\x33", 4), 
            2, 1, 0b11, 0b111111);


    return 0;
}
