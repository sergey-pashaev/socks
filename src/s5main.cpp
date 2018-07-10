#include <iostream>

#include <boost/asio.hpp>

#include "s5server.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <port>\n";
        return 1;
    }

    try {
        boost::asio::io_service io;
        boost::asio::ip::tcp::endpoint ep(
            boost::asio::ip::tcp::v4(),
            static_cast<uint16_t>(std::atoi(argv[1])));
        socks5::Server s{io, ep};
        io.run();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << '\n';
    }
    return 0;
}
