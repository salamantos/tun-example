#pragma once

#include <map>

namespace playground {

using ConnectionSideId = std::pair<std::string, int>;


struct ConnectionId {
    ConnectionSideId source;
    ConnectionSideId destination;

    ConnectionId revert()
    {
        return {destination, source};
    }
};


bool operator<(const ConnectionSideId& a, const ConnectionSideId& b)
{
    return a.first < b.first || (a.first == b.first && a.second < b.second);
}

bool operator<(const ConnectionId& a, const ConnectionId& b)
{
    return a.source < b.source || (a.source == b.source && a.destination < b.destination);
}


class TcpTracker {
private:
    std::map<ConnectionId, uint32_t> syn_offsets;

public:
    void mangle_tcp_header(nets::IPv4Packet& packet)
    {
        nets::TcpHeader* tcph = packet.raw_tcp();
        ConnectionSideId src_id = std::make_pair(packet.source_addr(), tcph->sport);
        ConnectionSideId dst_id = std::make_pair(packet.destination_addr(), tcph->dport);
        ConnectionId conn_id = {src_id, dst_id};

        if (tcph->syn && !tcph->ack) {
            // SYN
            syn_offsets[conn_id] = tcph->seq;
            tcph->seq = 0;
        }
        if (tcph->syn && tcph->ack) {
            // SYN-ACK
            syn_offsets[conn_id] = tcph->seq;
            tcph->seq = 0;
            tcph->ack_seq += syn_offsets[conn_id.revert()];
        }
        if (!tcph->syn) {
            // ESTABLISHED
            tcph->seq -= syn_offsets[conn_id];
            tcph->ack_seq += syn_offsets[conn_id.revert()];
        }

        packet.recompute_tcp_csum();
    }

};

}