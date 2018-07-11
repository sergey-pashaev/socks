#include "s5session.h"

#include <boost/log/trivial.hpp>

namespace socks5 {

Session::Session(_ctor_tag /*unused*/, ba::io_service& io)
    : downstream_socket_{io}, upstream_socket_{io} {}

std::unique_ptr<Session> Session::Create(ba::io_service& io) {
    return std::make_unique<Session>(_ctor_tag{}, io);
}

void Session::Start() {
    downstream_bytes_read_ = 0;
    BOOST_LOG_TRIVIAL(info) << "session=" << this << ' '
                            << downstream_socket_.local_endpoint() << " <- "
                            << downstream_socket_.remote_endpoint();

    ReadAuthRequest();
}

tcp::socket& Session::AcceptorSocket() { return downstream_socket_; }

std::size_t Session::AuthRequestSize() {
    const char nmethods = downstream_buf_[1];
    return 2 + nmethods;  // 2 = version + nmethods
}

void Session::ReadAuthRequest() {
    auto self(shared_from_this());
    auto handler = [this, self](const bs::error_code& ec, std::size_t length) {
        if (ec) {
            Close(ec);
            return;
        }

        downstream_bytes_read_ += length;
        const std::size_t auth_msg_min_size = 3;
        if (downstream_bytes_read_ < auth_msg_min_size) {
            ReadAuthRequest();
        } else {
            if (downstream_bytes_read_ < AuthRequestSize()) {
                ReadAuthMethods();
            } else {
                AuthResponse();
            }
        }
    };

    downstream_socket_.async_read_some(
        ba::buffer(downstream_buf_.data() + downstream_bytes_read_,
                   downstream_buf_.size() - downstream_bytes_read_),
        handler);
}

void Session::ReadAuthMethods() {
    auto self(shared_from_this());
    auto handler = [this, self](const bs::error_code& ec, std::size_t length) {
        if (ec) {
            Close(ec);
            return;
        }

        downstream_bytes_read_ += length;
        if (downstream_bytes_read_ < AuthRequestSize()) {
            ReadAuthMethods();
        } else {
            AuthResponse();
        }
    };

    downstream_socket_.async_read_some(
        ba::buffer(downstream_buf_.data() + downstream_bytes_read_,
                   downstream_buf_.size() - downstream_bytes_read_),
        handler);
}

void Session::AuthResponse() {
    auto self(shared_from_this());
    auto handler = [this, self](const bs::error_code& ec, std::size_t) {
        if (ec) {
            Close(ec);
            return;
        }

        downstream_bytes_read_ = 0;
        ReadRequest();
    };

    const std::size_t response_size = 2;
    downstream_buf_[0] = socks5::version;
    downstream_buf_[1] =
        static_cast<unsigned char>(socks5::AuthMethod::no_auth);

    BOOST_LOG_TRIVIAL(info) << "session=" << this << " no auth method";

    ba::async_write(downstream_socket_,
                    ba::buffer(downstream_buf_.data(), response_size), handler);
}

socks5::AddressType Session::RequestAddressType() const {
    return static_cast<socks5::AddressType>(downstream_buf_[3]);
}

std::size_t Session::RequestDomainNameSize() const {
    return static_cast<unsigned char>(downstream_buf_[4]);
}

std::size_t Session::RequestSize() const {
    switch (RequestAddressType()) {
        case socks5::AddressType::ipv4: {
            return 10;
            break;
        }
        case socks5::AddressType::domain_name: {
            return 7 + RequestDomainNameSize();
            break;
        }
        case socks5::AddressType::ipv6: {
            return 24;
            break;
        }
    }

    return 0;
}

std::string Session::RequestDomainName() const {
    return std::string(downstream_buf_.data() + 5, RequestDomainNameSize());
}

uint16_t Session::RequestPort() const {
    const std::size_t offset = [this]() -> std::size_t {
        switch (RequestAddressType()) {
            case socks5::AddressType::ipv4: {
                return 8;
                break;
            }
            case socks5::AddressType::domain_name: {
                return 5 + RequestDomainNameSize();
                break;
            }
            case socks5::AddressType::ipv6: {
                return 20;
                break;
            }
        }
    }();

    uint16_t port = downstream_buf_.at(offset);
    port = (port << 8) & 0xFF00;
    port = port | downstream_buf_.at(offset + 1);

    return port;
}

void Session::ReadRequest() {
    auto self(shared_from_this());
    auto handler = [this, self](const bs::error_code& ec, std::size_t length) {
        if (ec) {
            Close(ec);
            return;
        }

        downstream_bytes_read_ += length;
        const std::size_t request_min_size = 10;
        if (downstream_bytes_read_ < request_min_size) {
            ReadRequest();
        } else {
            const std::size_t request_size = RequestSize();
            if (request_size == 0) {
                Response(socks5::Reply::address_type_not_supported);
                return;
            }

            ReadRequest(request_size - downstream_bytes_read_);
        }
    };

    downstream_socket_.async_read_some(
        ba::buffer(downstream_buf_.data() + downstream_bytes_read_,
                   downstream_buf_.size() - downstream_bytes_read_),
        handler);
}

void Session::ReadRequest(std::size_t bytes_left) {
    if (!bytes_left) {
        ProcessRequest();
        return;
    }

    auto self(shared_from_this());
    auto handler = [this, self](const bs::error_code& ec, std::size_t length) {
        if (ec) {
            Close(ec);
            return;
        }

        downstream_bytes_read_ += length;
        ProcessRequest();
    };

    ba::async_read(
        downstream_socket_,
        ba::buffer(downstream_buf_.data() + downstream_bytes_read_, bytes_left),
        handler);
}

void Session::Response(socks5::Reply reply) {
    auto self(shared_from_this());
    auto handler = [this, self](const bs::error_code& ec, std::size_t) {
        if (ec) {
            Close(ec);
            return;
        }

        Close(bs::errc::make_error_code(bs::errc::success));
    };

    downstream_buf_[0] = socks5::version;
    downstream_buf_[1] = static_cast<unsigned char>(reply);
    downstream_buf_[2] = socks5::reserved;
    downstream_buf_[3] = static_cast<unsigned char>(RequestAddressType());

    const std::size_t response_size = RequestSize();  // same as request
    for (std::size_t i = 4; i < response_size; ++i) {
        downstream_buf_.at(i) = 0x00;
    }

    ba::async_write(downstream_socket_,
                    ba::buffer(downstream_buf_.data(), response_size), handler);
}

socks5::Command Session::RequestCommand() const {
    return static_cast<socks5::Command>(downstream_buf_[1]);
}

ba::ip::address Session::RequestAddress() const {
    const socks5::AddressType atype = RequestAddressType();
    if (atype == socks5::AddressType::ipv4) {
        ba::ip::address_v4::bytes_type bytes;
        for (std::size_t i = 0; i < 4; ++i) {  // 4 = ipv4 addr byte size
            bytes.at(i) = static_cast<unsigned char>(downstream_buf_.at(4 + i));
        }

        return ba::ip::address(ba::ip::address_v4(bytes));
    }

    if (atype == socks5::AddressType::ipv6) {
        ba::ip::address_v6::bytes_type bytes;
        for (std::size_t i = 0; i < 16; ++i) {  // 16 = ipv6 addr byte size
            bytes.at(i) = static_cast<unsigned char>(downstream_buf_.at(4 + i));
        }

        return ba::ip::address(ba::ip::address_v6(bytes));
    }

    return ba::ip::address();
}

void Session::ProcessRequest() {
    switch (RequestCommand()) {
        case socks5::Command::connect: {
            Connect();
            break;
        }
        case socks5::Command::bind: {
            Bind();
            break;
        }
        case socks5::Command::udp_associate: {
            UdpAssociate();
            break;
        }
        default:
            Response(socks5::Reply::command_not_supported);
            break;
    }
}

void Session::Connect() {
    if (RequestAddressType() == socks5::AddressType::domain_name) {
        auto resolver = std::make_shared<tcp::resolver>(
            downstream_socket_.get_io_service());
        auto self(shared_from_this());
        auto handler = [this, self, resolver](
            const bs::error_code& ec, tcp::resolver::iterator ep_iterator) {
            if (ec) {
                Close(ec);
                return;
            }

            Connect(ep_iterator);
        };

        tcp::resolver::query q{RequestDomainName(),
                               std::to_string(RequestPort())};

        BOOST_LOG_TRIVIAL(info) << "session=" << this << " resolve "
                                << q.host_name() << ':' << q.service_name();

        resolver->async_resolve(q, handler);
    } else {
        // fixme:
        tcp::endpoint ep{RequestAddress(), RequestPort()};
        auto ep_iterator = tcp::resolver::iterator::create(
            ep, RequestDomainName(), std::to_string(RequestPort()));
        Connect(ep_iterator);
    }
}

void Session::Connect(tcp::resolver::iterator ep_iterator) {
    // todo: add args
    if (!CheckAccess()) {
        Response(socks5::Reply::connection_not_allowed_by_ruleset);
        return;
    }

    auto self(shared_from_this());
    auto handler = [this, self](const bs::error_code& ec,
                                tcp::resolver::iterator it) {
        if (ec) {
            // todo: use Response(reply)
            Close(ec);
            return;
        }

        // todo: refactor ConnectResponse & Response into single function w/
        // std::function extra parameter, to replace Close() call in
        // Response()
        ConnectResponse(socks5::Reply::succeeded);
    };

    BOOST_LOG_TRIVIAL(info) << "session=" << this << " connect to "
                            << ep_iterator->endpoint();

    ba::async_connect(upstream_socket_, ep_iterator, handler);
}

void Session::ConnectResponse(socks5::Reply reply) {
    auto self(shared_from_this());
    auto handler = [this, self](const bs::error_code& ec, std::size_t) {
        if (ec) {
            Close(ec);
            return;
        }

        UpstreamRead();
        DownstreamRead();
    };

    downstream_buf_[0] = socks5::version;
    downstream_buf_[1] = static_cast<unsigned char>(reply);
    downstream_buf_[2] = socks5::reserved;
    downstream_buf_[3] = static_cast<unsigned char>(RequestAddressType());

    const std::size_t response_size = RequestSize();  // same as request
    for (std::size_t i = 4; i < response_size; ++i) {
        downstream_buf_.at(i) = 0x00;
    }

    ba::async_write(downstream_socket_,
                    ba::buffer(downstream_buf_.data(), response_size), handler);
}

void Session::Bind() {}                       // todo:
void Session::UdpAssociate() {}               // todo:
bool Session::CheckAccess() { return true; }  // todo:

void Session::Close(const bs::error_code& ec) {
    BOOST_LOG_TRIVIAL(info) << "session=" << this << " close: " << ec.message();

    if (downstream_socket_.is_open()) {
        downstream_socket_.close();
    }

    if (upstream_socket_.is_open()) {
        upstream_socket_.close();
    }
}

void Session::Relay(tcp::endpoint ep) {
    auto self(shared_from_this());
    auto handler = [this, self](const bs::error_code& ec) {
        if (!ec) {
            UpstreamRead();
            DownstreamRead();
        } else {
            Close(ec);
        }
    };

    upstream_socket_.async_connect(ep, handler);
}

void Session::UpstreamRead() {
    auto self(shared_from_this());
    auto handler = [this, self](const bs::error_code& ec, std::size_t length) {
        if (!ec) {
            BOOST_LOG_TRIVIAL(info)
                << "session=" << this << ' '
                << upstream_socket_.local_endpoint() << " <- "
                << upstream_socket_.remote_endpoint() << ' ' << length << 'b';

            DownstreamWrite(length);
        } else {
            Close(ec);
        }
    };

    upstream_socket_.async_read_some(
        ba::buffer(upstream_buf_.data(), upstream_buf_.size()), handler);
}

void Session::DownstreamRead() {
    auto self(shared_from_this());
    auto handler = [this, self](const bs::error_code& ec, std::size_t length) {
        if (!ec) {
            BOOST_LOG_TRIVIAL(info)
                << "session=" << this << ' '
                << downstream_socket_.local_endpoint() << " <- "
                << downstream_socket_.remote_endpoint() << ' ' << length << 'b';

            UpstreamWrite(length);
        } else {
            Close(ec);
        }
    };

    downstream_socket_.async_read_some(
        ba::buffer(downstream_buf_.data(), downstream_buf_.size()), handler);
}

void Session::DownstreamWrite(std::size_t length) {
    auto self(shared_from_this());
    auto handler = [this, self](const bs::error_code& ec, std::size_t length) {
        if (!ec) {
            BOOST_LOG_TRIVIAL(info)
                << "session=" << this << ' '
                << downstream_socket_.local_endpoint() << " -> "
                << downstream_socket_.remote_endpoint() << ' ' << length << 'b';

            UpstreamRead();
        } else {
            Close(ec);
        }
    };

    ba::async_write(downstream_socket_,
                    ba::buffer(upstream_buf_.data(), length), handler);
}

void Session::UpstreamWrite(std::size_t length) {
    auto self(shared_from_this());
    auto handler = [this, self](const bs::error_code& ec, std::size_t length) {
        if (!ec) {
            BOOST_LOG_TRIVIAL(info)
                << "session=" << this << ' '
                << upstream_socket_.local_endpoint() << " -> "
                << upstream_socket_.remote_endpoint() << ' ' << length << 'b';

            DownstreamRead();
        } else {
            Close(ec);
        }
    };

    ba::async_write(upstream_socket_,
                    ba::buffer(downstream_buf_.data(), length), handler);
}

}  // namespace socks5
