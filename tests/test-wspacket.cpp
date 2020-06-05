#include "../include/websocket_libuv.h"

void test_ws_packet(ROBuf remain, ROBuf income, bool finish, bool p_fin, uint8_t opcode, 
                    bool r1, bool r2, bool r3, size_t msize, size_t rsize) {
    auto x = WebSocketCommon::extractFrameFromData(remain, income);
    assert(x.m_has == finish);
    if(x.m_has) {
        assert(x.m_fin == p_fin);
        assert(x.m_opcode == opcode);
        assert(x.m_rsv1 == r1);
        assert(x.m_rsv2 == r2);
        assert(x.m_rsv3 == r3);
        assert(x.m_message.size() == msize);
    }
    assert(x.m_remain.size() == rsize);
}


int main() {
    test_ws_packet(ROBuf((char*)"\x82\x03", 2), ROBuf((char*)"hel", 3), true, true, 0x2,
                   false, false, false, 3, 0);
    test_ws_packet(ROBuf((char*)"\x82\x03", 2), ROBuf((char*)"helxxx", 6), true, true, 0x2,
                   false, false, false, 3, 3);
    test_ws_packet(ROBuf((char*)"\x82", 1), ROBuf((char*)"\x03helxxx", 7), true, true, 0x2,
                   false, false, false, 3, 3);
    test_ws_packet(ROBuf((char*)"\xa2", 1), ROBuf((char*)"\xaahelxxx", 7), false, true, 0x2,
                   false, true, false, 3, 8);
    test_ws_packet(ROBuf((char*)"\xa2", 1), 
            ROBuf((char*)"\x7e\x01\x00", 3) + ROBuf((char*)std::string(0x111, ' ').c_str(), 0x111), 
            true, true, 0x2,
            false, true, false, 0x100, 0x11);
    test_ws_packet(ROBuf((char*)"\xa2", 1), 
            ROBuf((char*)"\x7f\x00\x00\x00\x00\x00\x01\x00\x00", 9) + ROBuf((char*)std::string(0x11100, ' ').c_str(), 0x11100), 
            true, true, 0x2,
            false, true, false, 0x10000, 0x1100);
    test_ws_packet(ROBuf((char*)"\xa2", 1), 
            ROBuf((char*)"\x7f\x01\x00\x00\x00\x00\x01\x00\x00", 9) + ROBuf((char*)std::string(0x11100, ' ').c_str(), 0x11100), 
            false, true, 0x2,
            false, true, false, 0, 0x1110a);
    test_ws_packet(ROBuf(), 
            ROBuf((char*)"\xa2\x7f\x01\x00\x00\x00\x00\x01\x00\x00", 10) + ROBuf((char*)std::string(0x11100, ' ').c_str(), 0x11100), 
            false, true, 0x2,
            false, true, false, 0, 0x1110a);
    return 0;
}

