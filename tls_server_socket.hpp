//
// (C) 2018 Jens Páll Hafsteinsson, Axon ehf.
// 
// tls-socket is released under the Simplified BSD License (see LICENSE)

#pragma once

#include <botan/credentials_manager.h>
#include <botan/tls_session_manager.h>
#include <botan/tls_policy.h>

#include "tls_socket.hpp"

class tls_server_socket : public tls_socket
{
public:
    tls_server_socket(int socket,
                      Botan::TLS::Session_Manager& session_manager,
                      Botan::Credentials_Manager& credentials_manager,
                      const Botan::TLS::Policy& policy);
};
