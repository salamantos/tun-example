#pragma once

#include <mutex>
#include <atomic>
#include <iostream>

#include "nets.hpp"



namespace playground::logging {

static std::mutex logging_lock;
static std::atomic_bool do_log_packets = true;

void tcp(const std::string& title, const nets::IPv4Packet& packet)
{
    if (!do_log_packets.load(std::memory_order_relaxed))
        return;

    std::lock_guard lock(logging_lock);

    if (!title.empty())
        std::cout << title << " origin " << static_cast<std::string>(packet.origin) << '\n';
    std::cout << "From " << packet.source_addr() << ":" << packet.tcp_sport()
              << " to " << packet.destination_addr() << ":" << packet.tcp_dport() << '\n';
    std::cout << "SYN " << static_cast<int>(packet.flag_syn())
              << " ACK " << static_cast<int>(packet.flag_ack())
              << " RST " << static_cast<int>(packet.flag_rst())
              << " FIN " << static_cast<int>(packet.flag_fin()) << '\n';
    std::cout << "SeqNum " << packet.tcp_seqnum()
              << " AckNum " << packet.tcp_acknum() << '\n' << std::endl;
}


void ip(const std::string& title, const nets::IPv4Packet& packet)
{
    if (!do_log_packets.load(std::memory_order_relaxed))
        return;

    std::lock_guard lock(logging_lock);

    if (!title.empty())
        std::cout << title << " origin " << static_cast<std::string>(packet.origin) << '\n';
    std::cout << "From " << packet.source_addr()
              << " to " << packet.destination_addr() << '\n';
    std::cout << "TTL " << static_cast<int>(packet.ttl()) << " Proto " << static_cast<int>(packet.protocol()) << '\n';
    std::cout << "Total len " << static_cast<int>(packet.length()) << '\n' << std::endl;
}

void text(const std::string& text) {
    std::lock_guard lock(logging_lock);
    std::cout << text << std::endl;
}

void set_packet_logging_enabled(bool val) {
    do_log_packets.store(val);
}

}
