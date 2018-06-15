#ifndef SOCKS4_H
#define SOCKS4_H

#include <string>

#include <boost/asio.hpp>

namespace socks4 {

namespace ba = boost::asio;
namespace bs = boost::system;
using tcp = ba::ip::tcp;

const unsigned char version = 0x04;

class Request {
   public:
    enum class Command : unsigned char {
        connect = 0x01,
        bind = 0x02,
    };

    Request() = default;

    Request(Command cmd, tcp::endpoint& ep, const std::string& user)
        : version_(version), command_(cmd), user_(user), null_byte_(0) {
        if (ep.protocol() != tcp::v4()) {
            throw bs::system_error(ba::error::address_family_not_supported);
        }

        unsigned short port = ep.port();
        port_hi_ = (port >> 8) & 0xFF;
        port_lo_ = port & 0xFF;

        address_ = ep.address().to_v4().to_bytes();
    }

    typedef std::array<ba::const_buffer, 7> ConstBuffers;
    ConstBuffers buffers() const {
        ConstBuffers bufs = {{ba::buffer(&version_, 1),
                              ba::buffer(&command_, 1),
                              ba::buffer(&port_hi_, 1),
                              ba::buffer(&port_lo_, 1), ba::buffer(address_),
                              ba::buffer(user_), ba::buffer(&null_byte_, 1)}};

        return bufs;
    }

    typedef std::array<ba::mutable_buffer, 5> HeaderBuffers;
    HeaderBuffers header_buffers() {
        HeaderBuffers bufs = {{ba::buffer(&version_, 1),
                               ba::buffer(&command_, 1),
                               ba::buffer(&port_hi_, 1),
                               ba::buffer(&port_lo_, 1), ba::buffer(address_)}};

        return bufs;
    }

    Command command() const { return command_; }
    tcp::endpoint endpoint() const {
        unsigned short port = port_hi_;
        port = (port << 8) & 0xFF00;
        port = port | port_lo_;

        ba::ip::address_v4 address(address_);

        return tcp::endpoint(address, port);
    }

    std::string user() const { return user_; }
    void set_user(const std::string& user) { user_ = user; }

   private:
    unsigned char version_;
    Command command_;
    unsigned char port_hi_;
    unsigned char port_lo_;
    ba::ip::address_v4::bytes_type address_;
    std::string user_;
    unsigned char null_byte_;
};

class Response {
   public:
    enum class Status : unsigned char {
        granted = 0x5A,
        rejected = 0x5B,
        rejected_identd_no_connection = 0x5C,
        rejected_identd_different_userid = 0x5D
    };

    Response() = default;

    Response(Status status) : version_(0), status_(status) {}

    Response(Status status, tcp::endpoint ep)
        : version_(version), status_(status) {
        if (ep.protocol() != tcp::v4()) {
            throw bs::system_error(ba::error::address_family_not_supported);
        }

        unsigned short port = ep.port();
        port_hi_ = (port >> 8) & 0xFF;
        port_lo_ = port & 0xFF;

        address_ = ep.address().to_v4().to_bytes();
    }

    typedef std::array<ba::const_buffer, 5> ConstBuffers;
    ConstBuffers buffers() const {
        ConstBuffers bufs = {{ba::buffer(&version_, 1), ba::buffer(&status_, 1),
                              ba::buffer(&port_hi_, 1),
                              ba::buffer(&port_lo_, 1), ba::buffer(address_)}};

        return bufs;
    }

    typedef std::array<ba::mutable_buffer, 5> Buffers;
    Buffers buffers() {
        Buffers bufs = {{ba::buffer(&version_, 1), ba::buffer(&status_, 1),
                         ba::buffer(&port_hi_, 1), ba::buffer(&port_lo_, 1),
                         ba::buffer(address_)}};

        return bufs;
    }

    Status status() const { return status_; }

    tcp::endpoint endpoint() const {
        unsigned short port = port_hi_;
        port = (port << 8) & 0xFF00;
        port = port | port_lo_;

        ba::ip::address_v4 address(address_);

        return tcp::endpoint(address, port);
    }

   private:
    unsigned char version_;
    Status status_;
    unsigned char port_hi_;
    unsigned char port_lo_;
    ba::ip::address_v4::bytes_type address_;
};
};  // namespace socks4

#endif /* SOCKS4_H */
