#include <iostream>

#include <boost/array.hpp>
#include <boost/asio.hpp>

#include <gsl-lite.hpp>

int main(int argc, char* argv[]) {
    try {
        if (argc != 2) {
            std::cerr << "Usage: " << argv[0] << " <host>" << std::endl;
            return 1;
        }

        using boost::asio::ip::tcp;

        boost::asio::io_service io;
        tcp::resolver resolver(io);
        tcp::resolver::query query(argv[1], "daytime");
        auto endpoint_it = resolver.resolve(query);

        tcp::socket socket(io);
        boost::asio::connect(socket, endpoint_it);

        for (;;) {
            boost::array<char, 128> buf;
            boost::system::error_code error;

            size_t len = socket.read_some(boost::asio::buffer(buf), error);
            if (error == boost::asio::error::eof) {
                break;
            } else if (error) {
                throw boost::system::system_error(error);
            }

            std::cout.write(buf.data(), len);
        }
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
