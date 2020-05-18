#include "kpacket.h"
#include "robuf.h"

#include <uv.h>

#include <tuple>
#include <string>
#include <vector>

struct __client_selection_msg {
    uint8_t m_version;
    std::vector<uint8_t> m_methods;
};
/** @return {packet_finish, ...}  */
std::tuple<bool, struct __client_selection_msg, ROBuf> parse_client_hello(ROBuf remain, ROBuf income);

enum socks5_authentication_method: uint8_t {
    SOCKS5_AUTH_NO_REQUIRED = 0,
    SOCKS5_AUTH_GSSAPI,
    SOCKS5_AUTH_USERNAME_PASSWORD,
    SOCKS5_AUTH_NO_ACCEPTABLE = 0x77
};
PACK(
struct __server_selection_msg {
    uint8_t m_version;
    socks5_authentication_method m_method;
});

enum socks5_command_type: uint8_t {
    SOCKS5_CMD_CONNECT = 1,
    SOCKS5_CMD_BIND,
    SOCKS5_CMD_UDP
};
enum socks5_addr_type: uint8_t {
    SOCKS5_ADDR_IPV4 = 1,
    SOCKS5_ADDR_DOMAIN = 3,
    SOCKS5_ADDR_IPV6 = 4
};
struct __client_request_msg {
    uint8_t m_version;
    socks5_command_type m_command;
    uint8_t m_reserved;
    socks5_addr_type m_addr_type;
    std::string m_addr;
    uint16_t m_port;
};
/** @return {packet_finish, msg, remain_buffer, packet_error} packet_finish indicate 
 * whether the client request message is finish at this point. */
std::tuple<bool, struct __client_request_msg, ROBuf, bool> parse_client_request(ROBuf remain, ROBuf income);

enum socks5_reply_type: uint8_t {
    SOCKS5_REPLY_SUCCEEDED = 0,
    SOCKS5_REPLY_SERVER_FAILURE,
    SOCKS5_REPLY_CONNECTION_NOT_ALLOW_BY_RULE_SET,
    SOCKS5_REPLY_NETWORK_UNREACHABLE,
    SOCKS5_REPLY_HOST_UNREACHABLE,
    SOCKS5_REPLY_CONNECTION_REFUSED,
    SOCKS5_REPLY_TTL_EXPIRED,
    SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
    SOCKS5_REPLY_ADDRESSS_TYPE_NOT_SUPPORTED,
};
struct __server_reply_msg {
    uint8_t m_version;
    socks5_reply_type m_reply;
    uint8_t m_reserved;
    uint8_t m_addr_type;
    std::string m_addr;
    uint16_t m_port;
};

struct __socks5_username_password {
    uint8_t m_version;
    std::string m_username;
    std::string m_password;
};
/**  @return {packet_finish, msg} */
std::tuple<bool, struct __socks5_username_password, ROBuf> parse_username_authentication(ROBuf remain, ROBuf income);

struct __socks5_user_authentication_reply {
    uint8_t m_version;
    uint8_t m_status;
};

