//
// (C) 2018 Jens Páll Hafsteinsson, Axon ehf.
// 
// tls-socket is released under the Simplified BSD License (see LICENSE)

#pragma once

#include <botan/credentials_manager.h>
#include <botan/tls_session_manager.h>
#include <botan/tls_policy.h>

#include "tls_socket.hpp"

class tls_client_socket : public tls_socket
{
public:
    tls_client_socket(int socket,
                      Botan::TLS::Session_Manager& session_manager,
                      Botan::Credentials_Manager& credentials_manager,
                      const Botan::TLS::Policy& policy,
                      const std::string& hostname, uint16_t port);

protected:
    void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& cert_chain,
                               const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp,
                               const std::vector<Botan::Certificate_Store*>& trusted_roots,
                               Botan::Usage_Type usage,
                               const std::string& hostname,
                               const Botan::TLS::Policy& policy) override;
};
