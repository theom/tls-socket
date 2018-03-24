/*
* (C) 2014,2017 Jack Lloyd
*     2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* tls-socket is released under the Simplified BSD License (see license.txt)
*/

#pragma once

#if defined(_WIN32)

#include <winsock2.h>
#include <WS2tcpip.h>

typedef size_t ssize_t;

#define STDIN_FILENO _fileno(stdin)

inline void init_sockets()
{
    WSAData wsa_data;
    WORD wsa_version = MAKEWORD(2, 2);
    
    if (::WSAStartup(wsa_version, &wsa_data) != 0)
    {
        throw Botan_CLI::CLI_Error("WSAStartup() failed: " + std::to_string(WSAGetLastError()));
    }
    
    if (LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2)
    {
        ::WSACleanup();
        throw Botan_CLI::CLI_Error("Could not find a usable version of Winsock.dll");
    }
}

inline void stop_sockets()
{
    ::WSACleanup();
}

inline int close(int fd)
{
    return ::closesocket(fd);
}

inline int read(int s, void* buf, size_t len)
{
    return ::recv(s, reinterpret_cast<char*>(buf), static_cast<int>(len), 0);
}

inline int send(int s, const uint8_t* buf, size_t len, int flags)
{
    return ::send(s, reinterpret_cast<const char*>(buf), static_cast<int>(len), flags);
}

#else

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

inline void init_sockets() {}
inline void stop_sockets() {}

#endif
