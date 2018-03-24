//
// (C) 2014,2017 Jack Lloyd
//     2017 René Korthaus, Rohde & Schwarz Cybersecurity
//     2018 Jens Páll Hafsteinsson, Axon ehf.
// 
// tls-socket is released under the Simplified BSD License (see LICENSE)

#pragma once

#include <memory>

#include <botan/auto_rng.h>
#include <botan/pkcs8.h>
#include <botan/credentials_manager.h>
#include <botan/x509self.h>
#include <botan/data_src.h>

class base_credentials_manager : public Botan::Credentials_Manager
{
public:
    std::vector<Botan::Certificate_Store*>
    trusted_certificate_authorities(const std::string& type,
                                    const std::string& hostname) override
    {
        std::vector<Botan::Certificate_Store*> v;
        
        // don't ask for client certs
        if (type == "tls-server")
        {
            return v;
        }
        
        for (auto const& cs : this->certstores)
        {
            v.push_back(cs.get());
        }
        
        return v;
    }
    
protected:
    Botan::AutoSeeded_RNG rng;
    std::vector<std::shared_ptr<Botan::Certificate_Store>> certstores;
};

class server_credentials_manager : public base_credentials_manager
{
public:
    void set_server_cert(const std::string& server_cert)
    {
        this->server_cert = server_cert;
    }

    void set_server_key(const std::string& server_key, const std::string password)
    {
        this->server_key = server_key;
        this->server_key_password = password;
    }
    
    void load()
    {
        certificate_info cert;
        cert.key.reset(Botan::PKCS8::load_key(this->server_key, this->rng, this->server_key_password));
        
        Botan::DataSource_Stream in(this->server_cert);
        while (!in.end_of_data())
        {
            try
            {
                cert.certs.push_back(Botan::X509_Certificate(in));
            }
            catch (std::exception&)
            {
            }
        }
        
        this->creds.push_back(cert);
    }

    std::vector<Botan::X509_Certificate>
    cert_chain(const std::vector<std::string>& algos,
               const std::string& type,
               const std::string& hostname) override
    {
        BOTAN_UNUSED(type);
        
        for (auto const& i : this->creds)
        {
            if (std::find(algos.begin(), algos.end(), i.key->algo_name()) == algos.end())
            {
                continue;
            }
            
            if (hostname != "" && !i.certs[0].matches_dns_name(hostname))
            {
                continue;
            }
            
            return i.certs;
        }
        
        return std::vector<Botan::X509_Certificate>();
    }
    
    Botan::Private_Key*
    private_key_for (const Botan::X509_Certificate& cert,
                     const std::string& type,
                     const std::string& context) override
    {
        for (auto const& i : this->creds)
        {
            if (cert == i.certs[0])
            {
                return i.key.get();
            }
        }
        
        return nullptr;
    }

protected:
    std::string server_cert;
    std::string server_key;
    std::string server_key_password;
    
    struct certificate_info
    {
        std::vector<Botan::X509_Certificate> certs;
        std::shared_ptr<Botan::Private_Key> key;
    };
    
    std::vector<certificate_info> creds;
};

class client_credentials_manager : public base_credentials_manager
{
public:
    client_credentials_manager()
    {
        this->load_certstores();
    }
    
private:
    void load_certstores()
    {
        try
        {
            const std::vector<std::string> paths =
                {
                    "/etc/ssl/certs",
                    "/usr/share/ca-certificates",
                    "./certs"
                };
            
            for (auto const& path : paths)
            {
                auto cs = std::make_shared<Botan::Certificate_Store_In_Memory>(path);
                this->certstores.push_back(cs);
            }
        }
        catch (std::exception&)
        {
        }
    }
};
