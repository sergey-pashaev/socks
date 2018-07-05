#include "s5server.h"

namespace socks5 {

Server::Server(ba::io_service& io, tcp::endpoint ep) : acceptor_{io, ep} {
    Accept();
}

void Server::Accept() {
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

}  // namespace socks5
