#ifndef SOCKS5_H
#define SOCKS5_H

namespace socks5 {

const unsigned char version = 0x05;

enum class AuthMethod : unsigned char {
    no_auth = 0x00,
    gssapi = 0x01,
    username_password = 0x02,
    no_acceptable_methods = 0xFF,
};

enum class Command : unsigned char {
    connect = 0x01,
    bind = 0x02,
    udp_associate = 0x03,
};

const unsigned char reserved = 0x00;

enum class AddressType : unsigned char {
    ipv4 = 0x01,
    domain_name = 0x03,
    ipv6 = 0x04,
};

enum class Reply : unsigned char {
    succeeded = 0x00,
    general_socks_server_failure = 0x01,
    connection_not_allowed_by_ruleset = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,
};

// todo: add requests, replies fields offset enums

}  // namespace socks5

#endif /* SOCKS5_H */
