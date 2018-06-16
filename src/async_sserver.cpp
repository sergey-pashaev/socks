#include <iostream>
#include <memory>
#include <string>

#include <boost/array.hpp>
#include <boost/asio.hpp>

#include <socks/socks4.h>

namespace ba = boost::asio;
namespace bs = boost::system;
using tcp = ba::ip::tcp;

class Session : public std::enable_shared_from_this<Session> {
   private:
    struct _ctor_tag {
        explicit _ctor_tag() {}
    };

   public:
    Session(_ctor_tag, ba::io_service& io)
        : io_{io}, downstream_socket_{io}, upstream_socket_{io} {}

    static std::unique_ptr<Session> Create(ba::io_service& io) {
        return std::make_unique<Session>(_ctor_tag{}, io);
    }

    void Start() { ReadHeaders(); }

    tcp::socket& Socket() { return downstream_socket_; }

   private:
    void ReadHeaders() {
        auto self(shared_from_this());
        ba::async_read(
            downstream_socket_, request_.header_buffers(),
            [this, self](const bs::error_code& ec, std::size_t length) {
                if (!ec) {
                    ReadUserId();
                }
            });
    }

    void ReadUserId() {
        auto self(shared_from_this());
        ba::async_read_until(
            downstream_socket_, buf_, 0x00,
            [this, self](const bs::error_code& ec, std::size_t) {
                if (!ec) {
                    std::string user((std::istreambuf_iterator<char>(&buf_)),
                                     std::istreambuf_iterator<char>());
                    request_.set_user(user);

                    switch (request_.command()) {
                        case socks4::Request::Command::connect: {
                            Connect();
                            break;
                        }
                        case socks4::Request::Command::bind: {
                            Bind();
                            break;
                        }
                        // reject bad requests
                        default: { Reject(); }
                    }
                }
            });
    }

    socks4::Response::Status CheckAccess(const std::string&, tcp::endpoint) {
        // todo:
        return socks4::Response::Status::granted;
    }

    void Connect() {
        auto resp = std::make_shared<socks4::Response>(
            CheckAccess(request_.user(), request_.endpoint()));

        auto self(shared_from_this());
        ba::async_write(downstream_socket_, resp->buffers(),
                        [this, self, resp](const bs::error_code& ec,
                                           std::size_t written_bytes) {
                            switch (resp->status()) {
                                case socks4::Response::Status::granted: {
                                    Relay();
                                    break;
                                }
                                default:
                                    Close();
                                    break;
                            }
                        });
    }

    void Bind() {
        auto status = CheckAccess(request_.user(), request_.endpoint());

        tcp::endpoint ep{tcp::v4(), 0};
        auto acceptor = std::make_shared<tcp::acceptor>(io_, ep);
        auto resp = std::make_shared<socks4::Response>(
            status, acceptor->local_endpoint());

        auto self(shared_from_this());
        ba::async_write(
            downstream_socket_, resp->buffers(),
            [this, self, resp, acceptor](const bs::error_code& ec,
                                         std::size_t written_bytes) {
                switch (resp->status()) {
                    case socks4::Response::Status::granted: {
                        Accept(acceptor);
                        break;
                    }
                    default:
                        Close();
                        break;
                }
            });
    }

    void Reject() {
        auto resp = std::make_shared<socks4::Response>(
            socks4::Response::Status::rejected);

        auto self(shared_from_this());
        ba::async_write(
            downstream_socket_, resp->buffers(),
            [this, self, resp](const bs::error_code& ec,
                               std::size_t written_bytes) { Close(); });
    }

    void Accept(std::shared_ptr<tcp::acceptor> acceptor) {
        auto self(shared_from_this());
        acceptor->async_accept(
            upstream_socket_, [this, self, acceptor](const bs::error_code& ec) {
                if (!ec) {
                    UpstreamRead();
                    DownstreamRead();
                } else {
                    Close();
                }
            });
    }

    void Close() {
        if (downstream_socket_.is_open()) {
            downstream_socket_.close();
        }

        if (upstream_socket_.is_open()) {
            upstream_socket_.close();
        }
    }

    void Relay() {
        auto self(shared_from_this());
        upstream_socket_.async_connect(request_.endpoint(),
                                       [this, self](const bs::error_code& ec) {
                                           if (!ec) {
                                               UpstreamRead();
                                               DownstreamRead();
                                           } else {
                                               Close();
                                           }
                                       });
    }

    void UpstreamRead() {
        auto self(shared_from_this());
        upstream_socket_.async_read_some(
            ba::buffer(upstream_buf_),
            [this, self](const bs::error_code& ec, std::size_t length) {
                if (!ec) {
                    DownstreamWrite(length);
                } else {
                    Close();
                }
            });
    }

    void DownstreamRead() {
        auto self(shared_from_this());
        downstream_socket_.async_read_some(
            ba::buffer(downstream_buf_),
            [this, self](const bs::error_code& ec, std::size_t length) {
                if (!ec) {
                    UpstreamWrite(length);
                } else {
                    Close();
                }
            });
    }

    void DownstreamWrite(std::size_t length) {
        auto self(shared_from_this());
        async_write(downstream_socket_, ba::buffer(upstream_buf_, length),
                    [this, self](const bs::error_code& ec, std::size_t length) {
                        if (!ec) {
                            UpstreamRead();
                        } else {
                            Close();
                        }
                    });
    }

    void UpstreamWrite(std::size_t length) {
        auto self(shared_from_this());
        async_write(upstream_socket_, ba::buffer(downstream_buf_, length),
                    [this, self](const bs::error_code& ec, std::size_t length) {
                        if (!ec) {
                            DownstreamRead();
                        } else {
                            Close();
                        }
                    });
    }

   private:
    ba::io_service& io_;
    socks4::Request request_;
    ba::streambuf buf_;
    tcp::socket downstream_socket_;
    tcp::socket upstream_socket_;
    boost::array<char, 4096> upstream_buf_;
    boost::array<char, 4096> downstream_buf_;
};

class Server {
   public:
    Server(ba::io_service& io, tcp::endpoint ep) : io_{io}, acceptor_{io, ep} {
        Accept();
    }

   private:
    void Accept() {
        std::shared_ptr<Session> session(Session::Create(io_));
        acceptor_.async_accept(session->Socket(),
                               [this, session](const bs::error_code& ec) {
                                   if (!ec) {
                                       session->Start();
                                   }

                                   Accept();
                               });
    }

   private:
    ba::io_service& io_;
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
