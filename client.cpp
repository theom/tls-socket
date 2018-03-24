//
// (C) 2018 Jens Páll Hafsteinsson, Axon ehf.
// 
// tls-socket is released under the Simplified BSD License (see LICENSE)

#include <iostream>

#include "tls_client_socket.hpp"
#include "credentials.hpp"
#include "socket_utils.hpp"

class tls_client
{
public:
    tls_client()
    {
        init_sockets();
    }
    
    ~tls_client()
    {
        stop_sockets();
    }
    
    void run()
    {
        client_credentials_manager cm;
        
        Botan::TLS::Strict_Policy policy;
        
        Botan::TLS::Session_Manager_In_Memory sm(Botan::system_rng());

        const std::string host = "localhost";
        const std::string hostname = "";
        const uint16_t port = 1234;
        
        int s = connect_to_host(host, port);
        //this->set_socket_non_blocking(s);
        
        tls_client_socket socket(s, sm, cm, policy, hostname, port);
        
        fd_set writefds;
        FD_ZERO(&writefds);
        while (socket.is_open())
        {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_ZERO(&writefds);
            FD_SET(s, &readfds);

            if (socket.is_active())
            {
                FD_SET(STDIN_FILENO, &readfds);
            }
                
            if (socket.has_pending_send())
            {
                FD_SET(s, &writefds);
            }
            
            timeval timeout = {2, 0};
            ::select(s + 1, &readfds, &writefds, nullptr, nullptr);

            socket.set_can_read(FD_ISSET(s, &readfds));
            socket.set_can_write(FD_ISSET(s, &writefds));
            socket.send_receive();

            if (socket.has_pending_received())
            {
                uint8_t buffer[4 * 1024];
                ssize_t received_bytes = socket.read(buffer, sizeof(buffer));
                if (received_bytes > 0)
                {
                    std::string text(buffer, buffer + received_bytes - 1);
                    std::cout << "Received: '" << text << "'" << std::endl;
                }
            }
            
            if (FD_ISSET(STDIN_FILENO, &readfds))
            {
                uint8_t buffer[1024];
                ssize_t read_bytes = ::read(STDIN_FILENO, buffer, sizeof(buffer));
                if (read_bytes > 0)
                {
                    socket.write(buffer, read_bytes);
                }
            }
        }
    }
    
private:
    int connect_to_host(const std::string& host, uint16_t port)
    {
        addrinfo hints{0};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* first_addr;

        int res = ::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &first_addr);
        if (res != 0)
        {
            std::cout << "getaddrinfo: " << ::strerror(errno) << std::endl;
            ::exit(EXIT_FAILURE);
        }
        
        int s;
        addrinfo* addr;
        for (addr = first_addr; addr != nullptr; addr = addr->ai_next)
        {
            s = ::socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
            
            if (s == -1)
            {
                continue;
            }

            res = ::connect(s, addr->ai_addr, addr->ai_addrlen);
            if (res == -1)
            {
                ::close(s);
                continue;
            }
            
            break;
        }
        
        ::freeaddrinfo(first_addr);
        
        if (addr == nullptr)
        {
            std::cout << "Failed to connect: " << ::strerror(errno) << std::endl;
            ::exit(EXIT_FAILURE);
        }
        
        return s;
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
    tls_client c;
    c.run();
}
