#include "../include/websocket.hpp"

// class WebsocketCommon IMPLEMENTATION //{
/** static */
typename WebSocketCommon::ExtractReturnSingle WebSocketCommon::extractFrameFromData(ROBuf remain, ROBuf income) //{
{
    ExtractReturnSingle ret;
    ret.m_has = false;
    if(remain.size() + income.size() < sizeof(WSHeaderPartial)) {
        ret.m_remain = remain + income;
        return ret;
    }

    WSHeaderPartial header;
    if(remain.size() > 0)
        memcpy(&header, remain.base(), __MIN2(remain.size(), sizeof(WSHeaderPartial)));
    if(remain.size() < sizeof(WSHeaderPartial))
        memcpy(static_cast<char*>(static_cast<void*>(&header)) + __MIN2(remain.size(), sizeof(WSHeaderPartial)), 
               income.base(), sizeof(WSHeaderPartial) - remain.size());
    ret.m_fin = (header.FIN == 1);
    ret.m_opcode = static_cast<WebsocketOPCode>(header.OPCODE);
    ret.m_rsv1 = (header.RSV1 == 1);
    ret.m_rsv2 = (header.RSV2 == 1);
    ret.m_rsv3 = (header.RSV3 == 1);

    uint64_t data_offset = sizeof(WSHeaderPartial);
    bool mask = (header.MASK == 1);
    if(mask) data_offset += 4;

    uint8_t len1 = header.PAYLOAD_LEN;
    uint64_t len = 0;
    assert(len1 <= 127);
    if(len1 < 126) {
        len = len1;
    } else if(len1 == 126) {
        data_offset += 2;
        if(remain.size() + income.size() < data_offset + 126) {
            ret.m_remain = remain + income;
            return ret;
        }
        uint16_t uu;
        int f = 0;
        if(remain.size() > sizeof(WSHeaderPartial)) {
            f = __MIN2(sizeof(uu), remain.size() - sizeof(WSHeaderPartial));
            memcpy(&uu, remain.base() + sizeof(WSHeaderPartial), f);
        }
        if(remain.size() < sizeof(WSHeaderPartial) + sizeof(uu))
            memcpy(static_cast<char*>(static_cast<void*>(&uu)) + f,
                   f > 0 ? income.base() : income.base() + sizeof(WSHeaderPartial) - remain.size(), sizeof(uu) - f);
        len = k_ntohs(uu);
    } else {
        data_offset += 8;
        if(remain.size() + income.size() < data_offset + (1 << 16)) {
            ret.m_remain = remain + income;
            return ret;
        }
        uint64_t uu;
        int f = 0;
        if(remain.size() > sizeof(WSHeaderPartial)) {
            f = __MIN2(sizeof(uu), remain.size() - sizeof(WSHeaderPartial));
            memcpy(&uu, remain.base() + sizeof(WSHeaderPartial), f);
        }
        if(remain.size() < sizeof(WSHeaderPartial) + sizeof(uu))
            memcpy(static_cast<char*>(static_cast<void*>(&uu)) + f,
                   f > 0 ? income.base() : income.base() + sizeof(WSHeaderPartial) - remain.size(), sizeof(uu) - f);
        len = k_ntohll(uu);
    }

    if(len + data_offset > remain.size() + income.size()) {
        ret.m_remain = remain + income;
        return ret;
    } else {
        ret.m_has = true;
    }

    if(mask) {
        char mask_array[4];
        mask_array[0] = (remain.size() >= (data_offset - 3)) ? remain.base()[data_offset - 4]
                                                             : income.base()[data_offset - 4 - remain.size()];
        mask_array[1] = (remain.size() >= (data_offset - 2)) ? remain.base()[data_offset - 3]
                                                             : income.base()[data_offset - 3 - remain.size()];
        mask_array[2] = (remain.size() >= (data_offset - 1)) ? remain.base()[data_offset - 2]
                                                             : income.base()[data_offset - 2 - remain.size()];
        mask_array[3] = (remain.size() >= (data_offset - 0)) ? remain.base()[data_offset - 1]
                                                             : income.base()[data_offset - 1 - remain.size()];
        char* payload_start = remain.__base() + data_offset;
        size_t i=0;
        for(;i<len && (i + data_offset) < remain.size(); i++) {
            int j = (i % 4);
            payload_start[i] ^= mask_array[j];
        }
        payload_start = income.__base() + data_offset - remain.size();
        for(;i<len; i++) {
            int j = (i % 4);
            payload_start[i] ^= mask_array[j];
        }
    }

    if(data_offset < remain.size()) {
        int ff = __MIN2(len, remain.size() - data_offset);
        ret.m_message =  ROBuf(remain, ff, data_offset);
        if(ret.m_message.size() == len)
            ret.m_remain = ROBuf(remain, remain.size() - ff - data_offset, data_offset + ff);
        else
            ret.m_remain = ROBuf();
        if(ret.m_message.size() < len)
            ret.m_message = ret.m_message + ROBuf(income, len - ret.m_message.size(), 0);
        ret.m_remain = ret.m_remain + ROBuf(income, income.size() - len + ret.m_message.size(), len - ret.m_message.size());
    } else {
        ret.m_message = ROBuf(income, len, data_offset - remain.size());
        ret.m_remain = ROBuf(income, income.size() - len + remain.size() - data_offset, data_offset - remain.size() + len);
    }

    return ret;
} //}
/** static */
std::tuple<std::vector<typename WebSocketCommon::ExtractReturn>, ROBuf> WebSocketCommon::extractMultiFrameFromData(ROBuf remain, ROBuf income) //{
{
    std::vector<ExtractReturn> first;

    ExtractReturnSingle ss;
    while(true) {
        ss = extractFrameFromData(remain, income);
        remain = ss.m_remain;
        income = ROBuf();
        if(!ss.m_has) break;
        first.push_back(ss);
    }

    return std::make_tuple(first, remain);
} //}
/** static */
ROBuf WebSocketCommon::formFrameHeader(bool fin, WebsocketOPCode opcode, bool mask, ROBuf message, 
                                       bool rsv1, bool rsv2, bool rsv3) //{
{
    assert((uint8_t)opcode < (1 << 4));
    size_t buf_size = sizeof(WSHeaderPartial);
    if(mask) buf_size += 4;
    if(message.size() >= (1 << 16)) buf_size += 8;
    else if(message.size() >= 126)  buf_size += 2;

    ROBuf ret(buf_size);
    char* base = ret.__base();

    WSHeaderPartial* header = static_cast<decltype(header)>(static_cast<void*>(base));
    header->FIN = fin ? 1 : 0;
    header->RSV1= rsv1 ? 1 : 0;
    header->RSV2= rsv2 ? 1 : 0;
    header->RSV3= rsv3 ? 1 : 0;
    header->OPCODE = opcode;
    header->MASK = mask ? 1 : 0;
    if(message.size() < 126) 
        header->PAYLOAD_LEN = message.size();
    else if(message.size() < (1 << 16)) {
        header->PAYLOAD_LEN = 126;
        uint16_t* uu = static_cast<uint16_t*>(static_cast<void*>(base + sizeof(WSHeaderPartial)));
        *uu = k_htons(message.size());
    } else {
        header->PAYLOAD_LEN = 127;
        uint64_t* uu = static_cast<uint64_t*>(static_cast<void*>(base + sizeof(WSHeaderPartial)));
        *uu = k_htonll(message.size());
    }
    if(mask) {
        std::default_random_engine engine;
        std::uniform_int_distribution<uint8_t> distribution(0, 0xff);
        distribution(engine);
        char* mask_base = base + (buf_size - 4);
        mask_base[0] = distribution(engine);
        mask_base[1] = distribution(engine);
        mask_base[2] = distribution(engine);
        mask_base[3] = distribution(engine);
        for(size_t i=0; i<message.size(); i++) {
            int j = (i % 4);
            message.__base()[i] ^= mask_base[j];
        }
    }

    return ret;
} //}

/** constructor */
WebSocketCommon::WebSocketCommon(bool masked, bool save_fragment) //{
{
    this->m_save_fragment = save_fragment;

    this->m_masked = masked;
    this->m_recieve_end = false;

    this->m_write_buffer_size = 0;
    this->m_read_buffer_size = 0;

    this->m_state = WebsocketState::OPEN;
} //}
int WebSocketCommon::write_wrapper(ROBuf buf) //{
{
    this->m_write_buffer_size += buf.size();
    this->_write(buf, write_callback);
    if(this->m_write_buffer_size > WS_MAX_WRITE_BUFFER_SIZE)
        return (this->m_write_buffer_size - WS_MAX_WRITE_BUFFER_SIZE);
    else
        return 0;
} //}
void WebSocketCommon::write_callback(WebSocketCommon* obj, ROBuf buf, int status) //{
{
    if(obj == nullptr) return;
    obj->m_write_buffer_size -= buf.size();
    if(status < 0) 
        obj->emit("error", new WSEventError(obj, WebsocketError("websocket write error")));
    if(obj->m_write_buffer_size + buf.size() > WS_MAX_WRITE_BUFFER_SIZE && 
       obj->m_write_buffer_size < WS_MAX_WRITE_BUFFER_SIZE)
        obj->emit("drain", new WSEventDrain(obj));
} //}
void WebSocketCommon::read_callback(ROBuf buf, int status) //{
{
    this->m_read_buffer_size += buf.size();
    if(status < 0) {
        this->emit("error", new WSEventError(this, WebsocketError("websocket write error")));
        return;
    }

    auto x = WebSocketCommon::extractMultiFrameFromData(this->m_remain, buf);
    this->m_remain = std::get<1>(x);

    for(auto& packet: std::get<0>(x)) {
        switch(packet.m_opcode) {
            case WebsocketOPCode::Binary:
                this->emit("fragment", new WSEventFragment(this, packet.m_fin, packet.m_opcode, packet.m_message, 
                                                              packet.m_rsv1, packet.m_rsv2, packet.m_rsv3));
                if(packet.m_fin) {
                    this->emit("message", new WSEventMessage(this, packet.m_message));
                } else {
                    if(this->m_save_fragment) {
                        if(!this->m_remain.empty()) {
                            this->emit("error", new WSEventError(this, WebsocketError("invalid packet")));
                            return;
                        } else {
                            this->m_fragments = this->m_fragments + packet.m_message;
                            this->m_save_binary = true;
                        }
                    }
                }
                break;
            case WebsocketOPCode::Text:
                this->emit("fragment", new WSEventFragment(this, packet.m_fin, packet.m_opcode, packet.m_message, 
                                                              packet.m_rsv1, packet.m_rsv2, packet.m_rsv3));
                if(packet.m_fin) {
                    char* text = static_cast<char*>(malloc(packet.m_message.size() + 1));
                    text[packet.m_message.size()] = '\0';
                    memcpy(text, packet.m_message.base(), packet.m_message.size());
                    std::string str(text);
                    free(text);
                    this->emit("textMessage", new WSEventTextMessage(this, str));
                } else {
                    if(this->m_save_fragment) {
                        if(!this->m_remain.empty()) {
                            this->emit("error", new WSEventError(this, WebsocketError("invalid packet")));
                            return;
                        } else {
                            this->m_fragments = this->m_fragments + packet.m_message;
                            this->m_save_binary = false;
                        }
                    }
                }
                break;
            case WebsocketOPCode::Close:
                if(this->m_recieve_end) {
                    this->emit("error", new WSEventError(this, WebsocketError("double close from other endpoint")));
                    return;
                }
                if(packet.m_message.size() < 2) {
                    this->emit("error", new WSEventError(this, WebsocketError("close without reason")));
                    return;
                }
                this->m_recieve_end = true;
                this->m_state = WebsocketState::CLOSING;
                {
                    int status;
                    status = packet.m_message.base()[0] * 0xff + packet.m_message.base()[1];
                    char* msg = static_cast<char*>(malloc(packet.m_message.size() - 2 + 1));
                    if(packet.m_message.size() > 2) memcpy(msg, packet.m_message.base() + 2, packet.m_message.size() - 2);
                    msg[packet.m_message.size() - 2] = '\0';
                    std::string str(msg);
                    free(msg);
                    this->emit("end", new WSEventEnd(this, status, str));
                }
                break;
            case WebsocketOPCode::Ping:
            case WebsocketOPCode::Pong:
                if(packet.m_opcode == WebsocketOPCode::Ping) {
                    this->emit("ping", new WSEventPing(this, packet.m_message));
                } else {
                    this->emit("pong", new WSEventPing(this, packet.m_message));
                }
                break;
            case WebsocketOPCode::Continue:
                this->emit("fragment", new WSEventFragment(this, packet.m_fin, packet.m_opcode, packet.m_message, 
                                                              packet.m_rsv1, packet.m_rsv2, packet.m_rsv3));
                if(!this->m_save_fragment) break;
                if(this->m_fragments.size() == 0) {
                    this->emit("error", new WSEventError(this, WebsocketError("unexpected continue frame")));
                    return;
                }
                this->m_fragments = this->m_fragments + packet.m_message;
                if(packet.m_fin) {
                    if(this->m_save_binary) {
                        this->emit("message", new WSEventMessage(this, this->m_fragments));
                        this->m_fragments = ROBuf();
                    } else {
                        char* msg = static_cast<char*>(malloc(this->m_fragments.size() + 1));
                        msg[this->m_fragments.size()] = '\0';
                        memcpy(msg, this->m_fragments.base(), this->m_fragments.size());
                        std::string str(msg);
                        free(msg);
                        this->emit("textMessage", new WSEventTextMessage(this, str));
                        this->m_fragments = ROBuf();
                    }
                }
                break;
            default:
                this->emit("fragment", new WSEventFragment(this, packet.m_fin, packet.m_opcode, packet.m_message, 
                                                              packet.m_rsv1, packet.m_rsv2, packet.m_rsv3));
                break;
        }
    }
} //}
int WebSocketCommon::send(ROBuf buf) //{
{
    assert(this->m_state == WebsocketState::OPEN || 
          (this->m_state == WebsocketState::CLOSED && this->m_recieve_end));
    return this->sendFragment(true, WebsocketOPCode::Binary, this->m_masked, buf);
} //}
int WebSocketCommon::sendText(const std::string& str) //{
{
    assert(this->m_state == WebsocketState::OPEN || 
          (this->m_state == WebsocketState::CLOSED && this->m_recieve_end));
    ROBuf buf(str.size() + 1);
    memcpy(buf.__base(), str.c_str(), buf.size());
    buf.__base()[str.size()] = '\0';
    return this->sendFragment(true, WebsocketOPCode::Text, this->m_masked, buf);
} //}
int WebSocketCommon::sendFragment(bool fin, WebsocketOPCode opcode, bool mask, ROBuf msg,
                                     bool rsv1, bool rsv2, bool rsv3) //{
{
    auto header = formFrameHeader(fin, opcode, mask, msg,
                                  rsv1, rsv2, rsv3);
    this->write_wrapper(header);
    return this->write_wrapper(msg);
} //}
int WebSocketCommon::ping() //{
{
    assert(this->m_state == WebsocketState::OPEN || 
          (this->m_state == WebsocketState::CLOSED && this->m_recieve_end));
    return this->sendFragment(true, WebsocketOPCode::Ping, this->m_masked, ROBuf());
} //}
int WebSocketCommon::pong() //{
{
    assert(this->m_state == WebsocketState::OPEN || 
          (this->m_state == WebsocketState::CLOSED && this->m_recieve_end));
    return this->sendFragment(true, WebsocketOPCode::Pong, this->m_masked, ROBuf());
} //}
int WebSocketCommon::end(WebsocketStatusCode statusCode, const std::string& reason) //{
{
    assert(this->m_state != WebsocketState::CLOSED);
    if(this->m_state == WebsocketState::OPEN) {
        this->m_state = WebsocketState::CLOSING;
    } else {
        assert(this->m_recieve_end);
        this->m_state = WebsocketState::CLOSED;
    }
    size_t buf_size = 2 + reason.size();
    ROBuf bb(buf_size);
    uint16_t* status = static_cast<decltype(status)>(static_cast<void*>(bb.__base()));
    *status = k_htons(statusCode);
    memcpy(bb.__base() + 2, reason.c_str(), reason.size());
    return this->sendFragment(true, WebsocketOPCode::Close, this->m_masked, bb);
} //}
void WebSocketCommon::close() //{
{
    this->emit("close", new WSEventClose(this, this->m_state == WebsocketState::CLOSED));
    this->m_state = WebsocketState::CLOSED;
    return;
} //}
WebSocketCommon::~WebSocketCommon() {}
//}

WebSocketServer::WebSocketServer(bool save_fragment): WebSocketCommon(false, save_fragment) {}

WebSocketClient::WebSocketClient(bool save_fragment): WebSocketCommon(true, save_fragment) {}

