#include <ctime>
#include <iostream>
#include <string>

#include <boost/asio.hpp>

using boost::asio::ip::tcp;

std::string daytime_string() {
    using namespace std;
    time_t now = time(0);
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
