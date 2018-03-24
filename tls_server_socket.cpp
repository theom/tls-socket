//
// (C) 2018 Jens Páll Hafsteinsson, Axon ehf.
// 
// tls-socket is released under the Simplified BSD License (see LICENSE)

#include <botan/tls_server.h>

#include "tls_server_socket.hpp"

tls_server_socket::tls_server_socket(int socket,
                                     Botan::TLS::Session_Manager& session_manager,
                                     Botan::Credentials_Manager& credentials_manager,
                                     const Botan::TLS::Policy& policy)
    : tls_socket(socket)
{
    this->channel = std::make_unique<Botan::TLS::Server>(*this,
                                                         session_manager,
                                                         credentials_manager,
                                                         policy,
                                                         Botan::system_rng(),
                                                         false);
}
