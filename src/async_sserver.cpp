#include <iostream>
#include <memory>
#include <string>

#include <boost/asio.hpp>

#include <socks/socks4.h>

namespace ba = boost::asio;
namespace bs = boost::system;
using tcp = ba::ip::tcp;

class Session : public std::enable_shared_from_this<Session> {
   public:
    Session(ba::io_service& io, tcp::socket socket)
        : downstream_socket_{std::move(socket)}, upstream_socket_{io} {}

    void Start() { ReadHeaders(); }

   private:
    void ReadHeaders() {
        auto self(shared_from_this());
        ba::async_read(
            downstream_socket_, request_.header_buffers(),
            [this, self](const bs::error_code& ec, std::size_t length) {
                if (!ec) {
                    assert(length == 8);
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
                            ProcessConnect();
                            break;
                        }
                        case socks4::Request::Command::bind:
                            // todo:
                            break;
                    }
                }
            });
    }

    socks4::Response::Status CheckAccess(const std::string&, tcp::endpoint) {
        // todo:
        return socks4::Response::Status::granted;
    }

    void ProcessConnect() {
        auto resp = std::make_shared<socks4::Response>(
            CheckAccess(request_.user(), request_.endpoint()) /*,
                                                 request_.endpoint()*/);

        auto self(shared_from_this());
        ba::async_write(
            downstream_socket_, resp->buffers(),
            [this, self, resp](const bs::error_code& ec,
                               std::size_t written_bytes) {
                switch (resp->status()) {
                    case socks4::Response::Status::granted: {
                        std::cout << request_.user() << ' ' << "granted\n";
                        DoConnect();
                        break;
                    }
                    default:
                        std::cout << request_.user() << ' ' << "denied\n";
                        Close();
                        break;
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

    void DoConnect() {
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
    socks4::Request request_;
    ba::streambuf buf_;
    tcp::socket downstream_socket_;
    tcp::socket upstream_socket_;
    std::array<char, 4096> upstream_buf_;
    std::array<char, 4096> downstream_buf_;
};

class Server {
   public:
    Server(ba::io_service& io, tcp::endpoint ep)
        : acceptor_{io, ep}, socket_{io} {
        DoAccept(io);
    }

   private:
    void DoAccept(ba::io_service& io) {
        acceptor_.async_accept(socket_, [this, &io](const bs::error_code& ec) {
            if (!ec) {
                std::make_shared<Session>(io, std::move(socket_))->Start();
            }

            DoAccept(io);
        });
    }

   private:
    ba::ip::tcp::acceptor acceptor_;
    ba::ip::tcp::socket socket_;
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
