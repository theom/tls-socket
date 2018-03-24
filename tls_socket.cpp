//
// (C) 2018 Jens Páll Hafsteinsson, Axon ehf.
// 
// tls-socket is released under the Simplified BSD License (see LICENSE)

#include <iostream>
#include <unistd.h>

#include "tls_socket.hpp"
#include "socket_utils.hpp"

tls_socket::tls_socket(int socket)
    : socket(socket)
{
    this->closed = false;
}

void
tls_socket::set_can_read(bool flag)
{
    this->can_read = flag;
}

void
tls_socket::set_can_write(bool flag)
{
    this->can_write = flag;
}

void
tls_socket::send_receive()
{
    if (this->channel->is_closed() || this->closed)
    {
        // TODO: Do something better (e.g. throw or log)
        std::cout << "server_tls_socket::send_receive: Socket closed." << std::endl;
        return;
    }

    try
    {
        if (this->can_read) this->read_socket();
        if (this->can_write) this->write_socket();
    }
    catch (std::exception& e)
    {
        // TODO: Do something better (e.g. throw or log)
        std::cout << "server_tls_socket::send_receive: Error: " << e.what() << std::endl;
        ::close(this->socket);
        this->closed = true;
    }
}

bool
tls_socket::is_open()
{
    return !this->closed;
}

bool
tls_socket::is_active()
{
    return this->channel->is_active();
}

bool
tls_socket::has_pending_received()
{
    return this->pending_received.size() > 0;
}

bool
tls_socket::has_pending_send()
{
    return this->pending_send.size() > 0;
}

ssize_t
tls_socket::read(uint8_t* buffer, size_t size)
{
    if (!this->has_pending_received())
    {
        return 0;
    }

    auto entry = this->pending_received.front();
    
    auto start = entry.data() + this->receive_pos;
    auto entry_size = entry.size();
    ssize_t count = std::min<ssize_t>(size, entry_size - this->receive_pos);
    auto end = start + count;

    std::copy(start, end, buffer);

    this->receive_pos += count;
    if (entry_size == this->receive_pos)
    {
        this->pending_received.pop();
        this->receive_pos = 0;
    }
    
    return count;
}

ssize_t
tls_socket::write(uint8_t* buffer, size_t size)
{
    if (!this->channel->is_active())
    {
        return 0;
    }

    this->channel->send(buffer, size);

    return size;
}

void
tls_socket::print_stat()
{
    std::cout << "pending_received = " << this->pending_received.size()
              << " pending_send = " << this->pending_send.size()
              << std::endl;
}

// Protected

bool
tls_socket::tls_session_established(const Botan::TLS::Session& session)
{
    std::cout << "tls_session_established: Handshake complete, " << session.version().to_string()
              << " using " << session.ciphersuite().to_string() << std::endl;
    
    return true;
}

void
tls_socket::tls_record_received(uint64_t serial, const uint8_t* buffer, size_t size)
{
    // Only called with user data

    this->pending_received.emplace(buffer, buffer + size);
};

void
tls_socket::tls_emit_data(const uint8_t* buffer, size_t size)
{
    // Can be called multiple times for each tls_socket::write call

    if (!this->channel || !this->channel->is_active())
    {
        // Handshake in progress
        this->write_socket(buffer, size);
    }
    else
    {
        // Just collect the data and deal with it later in write_socket()
        this->pending_send.emplace(buffer, buffer + size);
    }
}

void
tls_socket::tls_alert(Botan::TLS::Alert alert)
{
    std::cout << "Alert: " << alert.type_string() << std::endl;
}

std::string
tls_socket::tls_server_choose_app_protocol(const std::vector<std::string>& app)
{
    return "1.0";
}

void
tls_socket::read_socket()
{
    uint8_t buffer[4 * 1024] = {0};
    ssize_t bytes_read = ::read(this->socket, buffer, sizeof(buffer));

    if (bytes_read == -1)
    {
        // TODO: Do something better (e.g. throw or log)
        std::cout << "tls_socket::read_socket: Error: " << std::strerror(errno) << std::endl;
    }
    else if (bytes_read == 0)
    {
        // TODO: Do something better (e.g. throw or log)
        std::cout << "tls_socket::read_socket: Other end closed the connection" << std::endl;
        this->channel->close();
        ::close(this->socket);
        this->closed = true;
    }
    else if (bytes_read > 0)
    {
        this->channel->received_data(buffer, bytes_read);
    }
}

void
tls_socket::write_socket()
{
    // Handshake socket writes are handled in tls_emit_data
    if (this->channel->is_active() && this->pending_send.size() > 0)
    {
        auto entry = this->pending_send.front();

        uint8_t* buffer = entry.data() + this->send_pos;
        size_t count = entry.size() - this->send_pos;
        
        ssize_t bytes_written = this->write_socket(buffer, count);
        if (bytes_written == count)
        {
            this->pending_send.pop();
            this->send_pos = 0;
        }
        else if (bytes_written > 0)
        {
            // Only part of the buffer was sent.
            // Keep track of where to start sending next time
            this->send_pos += bytes_written;
        }
    }
}

ssize_t
tls_socket::write_socket(const uint8_t* buffer, size_t size)
{
    ssize_t bytes_written = ::send(this->socket, buffer, size, MSG_NOSIGNAL);
        
    if (bytes_written < 0)
    {
        std::cout << "tls_socket::write_socket: Error: " << std::strerror(errno) << std::endl;
    }

    return bytes_written;
}
