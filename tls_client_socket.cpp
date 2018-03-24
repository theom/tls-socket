//
// (C) 2014,2017 Jack Lloyd
//     2017 René Korthaus, Rohde & Schwarz Cybersecurity
//     2018 Jens Páll Hafsteinsson, Axon ehf.
// 
// tls-socket is released under the Simplified BSD License (see LICENSE)

#include <iostream>

#include <botan/tls_client.h>
#include <botan/x509path.h>

#include "tls_client_socket.hpp"

tls_client_socket::tls_client_socket(int socket,
                                     Botan::TLS::Session_Manager& session_manager,
                                     Botan::Credentials_Manager& credentials_manager,
                                     const Botan::TLS::Policy& policy,
                                     const std::string& hostname, uint16_t port)
    : tls_socket(socket)
{
    this->channel = std::make_unique<Botan::TLS::Client>(*this,
                                                         session_manager,
                                                         credentials_manager,
                                                         policy,
                                                         Botan::system_rng(),
                                                         Botan::TLS::Server_Information(hostname, port));
}

// Protected

void
tls_client_socket::tls_verify_cert_chain(const std::vector<Botan::X509_Certificate>& cert_chain,
                                         const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp,
                                         const std::vector<Botan::Certificate_Store*>& trusted_roots,
                                         Botan::Usage_Type usage,
                                         const std::string& hostname,
                                         const Botan::TLS::Policy& policy)
{
    if (cert_chain.empty())
    {
        throw std::runtime_error("Certificate chain was empty");
    }
    
    Botan::Path_Validation_Restrictions restrictions(policy.require_cert_revocation_info(),
                                                     policy.minimum_signature_strength());
    
    //auto ocsp_timeout = std::chrono::milliseconds(1000);
    auto ocsp_timeout = std::chrono::milliseconds(0);  // This disables OCSP verification
    
    Botan::Path_Validation_Result result = Botan::x509_path_validate(cert_chain,
                                                                     restrictions,
                                                                     trusted_roots,
                                                                     hostname,
                                                                     usage,
                                                                     std::chrono::system_clock::now(),
                                                                     ocsp_timeout,
                                                                     ocsp);
    std::cout << "Certificate validation status: " << result.result_string() << std::endl;
    
    if (result.successful_validation())
    {
        auto status = result.all_statuses();
        
        if (status.size() > 0 &&
            status[0].count(Botan::Certificate_Status_Code::OCSP_RESPONSE_GOOD))
        {
            std::cout << "Valid OCSP response for this server" << std::endl;
        }
    }
}
