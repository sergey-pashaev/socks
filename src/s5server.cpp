#include <iostream>
#include <memory>
#include <string>

#include <boost/asio.hpp>

namespace ba = boost::asio;
namespace bs = boost::system;
using tcp = ba::ip::tcp;

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

class Session : public std::enable_shared_from_this<Session> {
   private:
    struct _ctor_tag {
        explicit _ctor_tag() {}
    };

   public:
    Session(_ctor_tag, ba::io_service& io)
        : downstream_socket_{io}, upstream_socket_{io} {}

    static std::unique_ptr<Session> Create(ba::io_service& io) {
        return std::make_unique<Session>(_ctor_tag{}, io);
    }

    void Start() {
        downstream_bytes_read_ = 0;
        ReadAuthRequest();
    }

    tcp::socket& AcceptorSocket() { return downstream_socket_; }

   private:
    std::size_t AuthRequestSize() {
        const char nmethods = downstream_buf_[1];
        return 2 + nmethods;  // 2 = version + nmethods
    }

    void ReadAuthRequest() {
        auto self(shared_from_this());
        auto handler = [this, self](const bs::error_code& ec,
                                    std::size_t length) {
            if (ec) {
                Close(ec.message());
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

    void ReadAuthMethods() {
        auto self(shared_from_this());
        auto handler = [this, self](const bs::error_code& ec,
                                    std::size_t length) {
            if (ec) {
                Close(ec.message());
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

    void AuthResponse() {
        auto self(shared_from_this());
        auto handler = [this, self](const bs::error_code& ec, std::size_t) {
            if (ec) {
                Close(ec.message());
                return;
            }

            downstream_bytes_read_ = 0;
            ReadRequest();
        };

        const std::size_t response_size = 2;
        downstream_buf_[0] = socks5::version;
        downstream_buf_[1] =
            static_cast<unsigned char>(socks5::AuthMethod::no_auth);

        ba::async_write(downstream_socket_,
                        ba::buffer(downstream_buf_.data(), response_size),
                        handler);
    }

    socks5::AddressType RequestAddressType() const {
        return static_cast<socks5::AddressType>(downstream_buf_[3]);
    }

    std::size_t RequestDomainNameSize() const { return downstream_buf_[4]; }

    std::size_t RequestSize() const {
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

    std::string RequestDomainName() const {
        return std::string(downstream_buf_.data() + 5, RequestDomainNameSize());
    }

    unsigned short RequestPort() const {
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

        unsigned short port = downstream_buf_[offset];
        port = (port << 8) & 0xFF00;
        port = port | downstream_buf_[offset + 1];

        return port;
    }

    void ReadRequest() {
        auto self(shared_from_this());
        auto handler = [this, self](const bs::error_code& ec,
                                    std::size_t length) {
            if (ec) {
                Close(ec.message());
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

    void ReadRequest(std::size_t bytes_left) {
        auto self(shared_from_this());
        auto handler = [this, self](const bs::error_code& ec,
                                    std::size_t length) {
            if (ec) {
                Close(ec.message());
                return;
            }

            downstream_bytes_read_ += length;
            ProcessRequest();
        };

        ba::async_read(
            downstream_socket_,
            ba::buffer(downstream_buf_.data() + downstream_bytes_read_,
                       bytes_left),
            handler);
    }

    void Response(socks5::Reply reply) {
        auto self(shared_from_this());
        auto handler = [this, self](const bs::error_code& ec, std::size_t) {
            if (ec) {
                Close(ec.message());
                return;
            }

            Close();
        };

        downstream_buf_[0] = socks5::version;
        downstream_buf_[1] = static_cast<unsigned char>(reply);
        downstream_buf_[2] = socks5::reserved;
        downstream_buf_[3] = static_cast<unsigned char>(RequestAddressType());

        const std::size_t response_size = RequestSize();  // same as request
        for (std::size_t i = 4; i < response_size; ++i) {
            downstream_buf_[i] = 0x00;
        }

        ba::async_write(downstream_socket_,
                        ba::buffer(downstream_buf_.data(), response_size),
                        handler);
    }

    socks5::Command RequestCommand() const {
        return static_cast<socks5::Command>(downstream_buf_[1]);
    }

    ba::ip::address RequestAddress() const {
        const socks5::AddressType atype = RequestAddressType();
        if (atype == socks5::AddressType::ipv4) {
            ba::ip::address_v4::bytes_type bytes;
            for (std::size_t i = 0; i < 4; ++i) {  // 4 = ipv4 addr byte size
                bytes[i] = static_cast<unsigned char>(downstream_buf_[4 + i]);
            }
            return ba::ip::address(ba::ip::address_v4(bytes));
        } else if (atype == socks5::AddressType::ipv6) {
            ba::ip::address_v6::bytes_type bytes;
            for (std::size_t i = 0; i < 16; ++i) {  // 16 = ipv6 addr byte size
                bytes[i] = static_cast<unsigned char>(downstream_buf_[4 + i]);
            }
            return ba::ip::address(ba::ip::address_v6(bytes));
        }

        return ba::ip::address();
    }

    void ProcessRequest() {
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

    void Connect() {
        if (RequestAddressType() == socks5::AddressType::domain_name) {
            auto resolver = std::make_shared<tcp::resolver>(
                downstream_socket_.get_io_service());
            auto self(shared_from_this());
            auto handler = [this, self, resolver](
                const bs::error_code& ec, tcp::resolver::iterator ep_iterator) {
                if (ec) {
                    Close(ec.message());
                    return;
                }

                Connect(ep_iterator);
            };

            tcp::resolver::query q{RequestDomainName(),
                                   std::to_string(RequestPort())};
            resolver->async_resolve(q, handler);
        } else {
            // fixme:
            tcp::endpoint ep{RequestAddress(), RequestPort()};
            auto ep_iterator = tcp::resolver::iterator::create(
                ep, RequestDomainName(), std::to_string(RequestPort()));
            Connect(ep_iterator);
        }
    }

    void Connect(tcp::resolver::iterator ep_iterator) {
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
                Close(ec.message());
                return;
            }

            // todo: refactor ConnectResponse & Response into single function w/
            // std::function extra parameter, to replace Close() call in
            // Response()
            ConnectResponse(socks5::Reply::succeeded);
        };

        ba::async_connect(upstream_socket_, ep_iterator, handler);
    }

    void ConnectResponse(socks5::Reply reply) {
        auto self(shared_from_this());
        auto handler = [this, self](const bs::error_code& ec, std::size_t) {
            if (ec) {
                Close(ec.message());
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
            downstream_buf_[i] = 0x00;
        }

        ba::async_write(downstream_socket_,
                        ba::buffer(downstream_buf_.data(), response_size),
                        handler);
    }

    void Bind() {}                       // todo:
    void UdpAssociate() {}               // todo:
    bool CheckAccess() { return true; }  // todo:

    void Close(std::string msg = std::string()) {
        std::cerr << msg << '\n';
        if (downstream_socket_.is_open()) {
            downstream_socket_.close();
        }

        if (upstream_socket_.is_open()) {
            upstream_socket_.close();
        }
    }

    void Relay(tcp::endpoint ep) {
        auto self(shared_from_this());
        auto handler = [this, self](const bs::error_code& ec) {
            if (!ec) {
                UpstreamRead();
                DownstreamRead();
            } else {
                Close(ec.message());
            }
        };

        upstream_socket_.async_connect(ep, handler);
    }

    void UpstreamRead() {
        auto self(shared_from_this());
        auto handler = [this, self](const bs::error_code& ec,
                                    std::size_t length) {
            if (!ec) {
                DownstreamWrite(length);
            } else {
                Close(ec == ba::error::eof ? "" : ec.message());
            }
        };

        upstream_socket_.async_read_some(
            ba::buffer(upstream_buf_.data(), upstream_buf_.size()), handler);
    }

    void DownstreamRead() {
        auto self(shared_from_this());
        auto handler = [this, self](const bs::error_code& ec,
                                    std::size_t length) {
            if (!ec) {
                UpstreamWrite(length);
            } else {
                Close(ec == ba::error::eof ? "" : ec.message());
            }
        };

        downstream_socket_.async_read_some(
            ba::buffer(downstream_buf_.data(), downstream_buf_.size()),
            handler);
    }

    void DownstreamWrite(std::size_t length) {
        auto self(shared_from_this());
        auto handler = [this, self](const bs::error_code& ec,
                                    std::size_t length) {
            if (!ec) {
                UpstreamRead();
            } else {
                Close(ec == ba::error::eof ? "" : ec.message());
            }
        };

        ba::async_write(downstream_socket_,
                        ba::buffer(upstream_buf_.data(), length), handler);
    }

    void UpstreamWrite(std::size_t length) {
        auto self(shared_from_this());
        auto handler = [this, self](const bs::error_code& ec,
                                    std::size_t length) {
            if (!ec) {
                DownstreamRead();
            } else {
                Close(ec == ba::error::eof ? "" : ec.message());
            }
        };

        ba::async_write(upstream_socket_,
                        ba::buffer(downstream_buf_.data(), length), handler);
    }

   private:
    std::size_t downstream_bytes_read_ = 0;
    tcp::socket downstream_socket_;
    tcp::socket upstream_socket_;
    std::array<char, 4096> upstream_buf_;
    std::array<char, 4096> downstream_buf_;
};

class Server {
   public:
    Server(ba::io_service& io, tcp::endpoint ep) : acceptor_{io, ep} {
        Accept();
    }

   private:
    void Accept() {
        std::shared_ptr<Session> session{
            Session::Create(acceptor_.get_io_service())};

        auto accept_handler = [this, session](const bs::error_code& ec) {
            if (!ec) {
                session->Start();
            }

            Accept();
        };

        acceptor_.async_accept(session->AcceptorSocket(), accept_handler);
    }

   private:
    ba::ip::tcp::acceptor acceptor_;
};

int main(int argc, char* argv[]) {
    try {
        ba::io_service io;
        tcp::endpoint ep(tcp::v4(),
                         static_cast<unsigned short>(std::atoi(argv[1])));
        Server s{io, ep};
        io.run();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << '\n';
    }
    return 0;
}
