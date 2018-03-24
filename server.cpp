//
// (C) 2018 Jens Páll Hafsteinsson, Axon ehf.
// 
// tls-socket is released under the Simplified BSD License (see LICENSE)

#include <iostream>
#include <fcntl.h>

#include "tls_server_socket.hpp"
#include "credentials.hpp"
#include "socket_utils.hpp"

class my_policy : public Botan::TLS::Strict_Policy
{
public:
    bool require_cert_revocation_info() const override
    {
        return false;
    }
};

class tls_server
{
public:
    tls_server()
    {
        init_sockets();
        this->port = 1234;
    }
    
    ~tls_server()
    {
        stop_sockets();
    }
    
    void run()
    {
        server_credentials_manager cm;
        cm.set_server_cert("certs/server_cert.pem");
        cm.set_server_key("keys/server_private_key.pem", "Abcde123!");
        cm.load();

        my_policy policy;

        Botan::TLS::Session_Manager_In_Memory sm(Botan::system_rng());

        this->create_listening_socket();

        while(true)
        {
            std::cout << "accepting connection" << std::endl;
            int s = ::accept(this->listen_socket, nullptr, nullptr);
            //this->set_socket_non_blocking(s);

            std::cout << "New connection" << std::endl;
            
            tls_server_socket socket(s, sm, cm, policy);
            
            fd_set writefds;
            FD_ZERO(&writefds);
            while (socket.is_open())
            {
                fd_set readfds;
                FD_ZERO(&readfds);
                FD_ZERO(&writefds);
                FD_SET(s, &readfds);

                if (socket.has_pending_send())
                {
                    FD_SET(s, &writefds);
                }
                
                ::select(s + 1, &readfds, &writefds, nullptr, nullptr);
                
                socket.set_can_read(FD_ISSET(s, &readfds));
                socket.set_can_write(FD_ISSET(s, &writefds));
                socket.send_receive();

                while (socket.has_pending_received())
                {
                    uint8_t buffer[4 * 1024];
                    ssize_t received_bytes = socket.read(buffer, sizeof(buffer));
                    if (received_bytes > 0)
                    {
                        std::string text(buffer, buffer + received_bytes - 1);
                        std::cout << "Received '" << text << "'" << std::endl;
                        socket.write(buffer, received_bytes);
                    }
                }
            }
        }
    }
    
private:
    short port;
    int listen_socket;

    void create_listening_socket()
    {
        this->listen_socket = ::socket(PF_INET, SOCK_STREAM, 0);
        if (this->listen_socket == -1)
        {
            std::cout << "socket: " << ::strerror(errno) << std::endl;
            ::exit(EXIT_FAILURE);
        }
        
        int res;

        int enable = 1;
        res = setsockopt(this->listen_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
        if (res < 0)
        {
            ::close(this->listen_socket);
            std::cout << "setsockopt: " << ::strerror(errno) << std::endl;
            ::exit(EXIT_FAILURE);
        }
        
        sockaddr_in socket_info;
        ::memset(&socket_info, 0, sizeof(socket_info));
        socket_info.sin_family = AF_INET;
        socket_info.sin_port = htons(this->port);
        socket_info.sin_addr.s_addr = INADDR_ANY;

        res = ::bind(this->listen_socket, reinterpret_cast<struct sockaddr*>(&socket_info), sizeof(struct sockaddr));
        if (res == -1)
        {
            ::close(this->listen_socket);
            std::cout << "bind: " << ::strerror(errno) << std::endl;
            ::exit(EXIT_FAILURE);
        }

        res = ::listen(this->listen_socket, 100);
        if (res == -1)
        {
            ::close(this->listen_socket);
            std::cout << "listen: " << ::strerror(errno) << std::endl;
            ::exit(EXIT_FAILURE);
        }
    }

    void set_socket_non_blocking(int socket)
    {
        int res;
        
#ifdef _WIN32
        unsigned long mode = 1;
        res = ioctlsocket(socket, FIONBIO, &mode);
        if (ser != 0)
        {
            std::cout << "ioctlsocket error" << std::endl;
            ::exit(EXIT_FAILURE);
        }
#else
        int flags = fcntl(socket, F_GETFL, 0);
        if (flags == -1)
        {
            std::cout << "fcntl get: " << ::strerror(errno) << std::endl;
            ::exit(EXIT_FAILURE);
        }
        flags |= O_NONBLOCK;
        res = fcntl(socket, F_SETFL, flags);
        if (res != 0)
        {
            std::cout << "fcntl set: " << ::strerror(errno) << std::endl;
            ::exit(EXIT_FAILURE);
        }
#endif
    }
};

int
main()
{
    tls_server s;
    s.run();
}
