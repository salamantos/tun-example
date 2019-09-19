#pragma once

#include <mutex>
#include <iostream>

#include "nets.hpp"



namespace playground::logging {

std::mutex logging_lock;

void tcp(const std::string& title, const nets::IPv4Packet& packet)
{
    std::lock_guard lock(logging_lock);

    if (!title.empty())
        std::cout << title << " origin " << static_cast<int>(packet.origin_id) << '\n';
    std::cout << "From " << packet.source_addr() << ":" << packet.tcp_sport()
              << " to " << packet.destination_addr() << ":" << packet.tcp_dport() << '\n';
    std::cout << "SYN " << static_cast<int>(packet.flag_syn())
              << " ACK " << static_cast<int>(packet.flag_ack())
              << " FIN " << static_cast<int>(packet.flag_fin()) << '\n';
    std::cout << "SeqNum " << packet.tcp_seqnum()
              << " AckNum " << packet.tcp_acknum() << '\n' << std::endl;
}


void ip(const std::string& title, const nets::IPv4Packet& packet)
{
    std::lock_guard lock(logging_lock);

    if (!title.empty())
        std::cout << title << " origin " << static_cast<int>(packet.origin_id) << '\n';
    std::cout << "From " << packet.source_addr()
              << " to " << packet.destination_addr() << '\n';
    std::cout << "TTL " << static_cast<int>(packet.ttl()) << '\n';
    std::cout << "Total len " << static_cast<int>(packet.length()) << '\n' << std::endl;
}

void text(const std::string& text) {
    std::lock_guard lock(logging_lock);
    std::cout << text << std::endl;
}

}