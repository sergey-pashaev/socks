#ifndef S5SERVER_H
#define S5SERVER_H

#include <memory>

#include <boost/asio.hpp>

#include "s5session.h"

namespace ba = boost::asio;
namespace bs = boost::system;
using tcp = ba::ip::tcp;

namespace socks5 {

class Server {
   public:
    Server(ba::io_service& io, tcp::endpoint ep);

   private:
    void Accept();

   private:
    ba::ip::tcp::acceptor acceptor_;
};

}  // namespace socks5

#endif /* S5SERVER_H */
