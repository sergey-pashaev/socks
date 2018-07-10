#ifndef S5SESSION_H
#define S5SESSION_H

#include <iostream>
#include <memory>
#include <string>

#include <boost/asio.hpp>

#include <socks/socks5.h>

namespace ba = boost::asio;
namespace bs = boost::system;
using tcp = ba::ip::tcp;

namespace socks5 {

class Session : public std::enable_shared_from_this<Session> {
   private:
    struct _ctor_tag {
        explicit _ctor_tag() = default;
    };

   public:
    Session(_ctor_tag /*unused*/, ba::io_service& io);

    static std::unique_ptr<Session> Create(ba::io_service& io);

    void Start();

    tcp::socket& AcceptorSocket();

   private:
    std::size_t AuthRequestSize();

    void ReadAuthRequest();

    void ReadAuthMethods();

    void AuthResponse();

    socks5::AddressType RequestAddressType() const;

    std::size_t RequestDomainNameSize() const;

    std::size_t RequestSize() const;

    std::string RequestDomainName() const;

    uint16_t RequestPort() const;

    void ReadRequest();

    void ReadRequest(std::size_t bytes_left);

    void Response(socks5::Reply reply);

    socks5::Command RequestCommand() const;

    ba::ip::address RequestAddress() const;

    void ProcessRequest();

    void Connect();

    void Connect(tcp::resolver::iterator ep_iterator);

    void ConnectResponse(socks5::Reply reply);

    void Bind();
    void UdpAssociate();
    bool CheckAccess();

    void Close(const bs::error_code& ec);

    void Relay(tcp::endpoint ep);

    void UpstreamRead();

    void DownstreamRead();

    void DownstreamWrite(std::size_t length);

    void UpstreamWrite(std::size_t length);

   private:
    std::size_t downstream_bytes_read_ = 0;
    tcp::socket downstream_socket_;
    tcp::socket upstream_socket_;
    std::array<char, 4096> upstream_buf_;
    std::array<char, 4096> downstream_buf_;
};

}  // namespace socks5

#endif /* S5SESSION_H */
