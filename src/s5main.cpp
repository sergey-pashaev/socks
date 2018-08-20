#include <iostream>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/log/trivial.hpp>

#include "s5server.h"

void run(boost::asio::io_service& io, uint16_t port) {
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), port);
    socks5::Server s{io, ep};
    io.run();
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <port>\n";
        return 1;
    }

    const uint16_t port = std::atoi(argv[1]);
    boost::asio::io_service io;

    // stop io service on SIGINT/SIGTERM
    boost::asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait(
        [&io](const boost::system::error_code&, int) { io.stop(); });

    // restart server until io service isn't stopped & log exceptions
    do {
        try {
            run(io, port);
        } catch (std::exception& e) {
            BOOST_LOG_TRIVIAL(error) << "exception: " << e.what();
            BOOST_LOG_TRIVIAL(info) << "restart server...";
        }
    } while (!io.stopped());

    return 0;
}
