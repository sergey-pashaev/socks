#include <chrono>
#include <ctime>
#include <iostream>
#include <string>

#include <boost/asio.hpp>

using boost::asio::ip::tcp;

std::string daytime_string() {
    using std::chrono::system_clock;
    system_clock::time_point tp = system_clock::now();
    std::time_t now = system_clock::to_time_t(tp);
    return ctime(&now);
}

int main() {
    try {
        boost::asio::io_service io;
        tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 13));

        for (;;) {
            tcp::socket socket(io);
            acceptor.accept(socket);

            std::string msg = daytime_string();

            boost::system::error_code error;
            boost::asio::write(socket, boost::asio::buffer(msg), error);
        }
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
}
