//
// (C) 2018 Jens Páll Hafsteinsson, Axon ehf.
// 
// tls-socket is released under the Simplified BSD License (see LICENSE)

#pragma once

#include <queue>
#include <vector>

#include <botan/tls_callbacks.h>
#include <botan/tls_channel.h>

class tls_socket : public Botan::TLS::Callbacks
{
public:
    tls_socket(int socket);

    void set_can_read(bool flag);
    void set_can_write(bool flag);
    void send_receive();
    bool is_open();
    bool is_active();
    bool has_pending_received();
    bool has_pending_send();

    ssize_t read(uint8_t* buffer, size_t size);
    ssize_t write(uint8_t* buffer, size_t size);

    void print_stat();
    
protected:
    int socket;
    bool closed = false;
    bool can_read = false;
    bool can_write = false;
    std::unique_ptr<Botan::TLS::Channel> channel;
    std::queue<std::vector<uint8_t>> pending_received;
    std::queue<std::vector<uint8_t>> pending_send;
    size_t receive_pos = 0;
    size_t send_pos = 0;

    void read_socket();
    void write_socket();
    ssize_t write_socket(const uint8_t* buffer, size_t size);

    bool tls_session_established(const Botan::TLS::Session& session) override;
    void tls_record_received(uint64_t serial, const uint8_t input[], size_t input_len) override;
    void tls_emit_data(const uint8_t buf[], size_t length) override;
    void tls_alert(Botan::TLS::Alert alert) override;
    std::string tls_server_choose_app_protocol(const std::vector<std::string>& app) override;
};
