#pragma once

#include <map>
#include <variant>
#include <chrono>
#include <fstream>

#include "nets.hpp"
#include "logging.hpp"



namespace playground {

class NoMoreData : public std::runtime_error {
public:
    NoMoreData()
        : runtime_error("No more data")
    {}
};


class TcpEncoder {
private:
    std::ofstream file;

public:
    TcpEncoder() = default;

    explicit TcpEncoder(const std::string& path)
        : file(path)
    {}

    void write_next(const nets::DataPiece& piece)
    {
        file << piece.timestamp << ' ' << piece.data.length() << ' ';
        file << piece.connection_id << ' ' << piece.direction << '\n';
        file.write(piece.data.data(), piece.data.length());

        // sync sometimes
        if ((piece.timestamp & 0xff00u) < 0x3000u)
            file.flush();
    }
};


class TcpDecoder {
private:
    std::ifstream file;
    std::mutex lock;

    std::map<nets::ConnectionId, std::deque<nets::DataPiece>> piecies;

public:
    TcpDecoder() = default;

    explicit TcpDecoder(const std::string& path)
        : file(path)
    {}

    nets::DataPiece next_tcp(const nets::ConnectionId& id)
    {
        std::lock_guard guard(lock);

        while (piecies[id].empty())
            read_more();

        auto buf = piecies[id].back();
        piecies[id].pop_back();
        return buf;
    }

private:
    void read_more()
    {
        auto piece = read_next();
        piecies[piece.connection_id].push_front(std::move(piece));
    }

    nets::DataPiece read_next()
    {
        size_t len;
        nets::DataPiece piece;

        file >> piece.timestamp >> len >> piece.connection_id >> piece.direction;
        if (file.fail()) {
            throw NoMoreData{};
        }

        std::string dummy;
        std::getline(file, dummy);

        char* data = new char[len];
        file.read(data, len);
        piece.data = std::string(data, len);
        delete[] data;

        if (file.fail()) {
            throw NoMoreData{};
        }

        return piece;
    }
};


class RecordingInterceptor : public nets::PipeInterceptor {
private:
    std::shared_ptr<TcpEncoder> encoder;
    nets::ConnectionId connection_id;
    DataWriter writer;

public:
    RecordingInterceptor(std::shared_ptr<TcpEncoder> encoder, const nets::ConnectionId& connection_id)
        : encoder(encoder), connection_id(connection_id)
    {}

    void set_writer(DataWriter w) override
    {
        writer = w;
    }

    void put(const nets::DataPiece& piece) override
    {
        try {
            writer(piece);
            encoder->write_next(piece);
        } catch (std::runtime_error& err) {
            logging::text(err.what());
        }
    }
};


void simple_replayer(nets::ConnectionId connection_id,
                     std::shared_ptr<TcpDecoder> decoder, nets::PipeInterceptor::DataWriter writer)
{
    unsigned int shutdowns = 0;
    try {
        while (shutdowns < 2) {
            const nets::DataPiece piece = decoder->next_tcp(connection_id);
            if (piece.is_connection_shutdown())
                ++shutdowns;
            writer(piece);
        }
    } catch (NoMoreData&) {}
}

void time_based_replayer(double speed_mul, nets::ConnectionId connection_id,
                         std::shared_ptr<TcpDecoder> decoder, nets::PipeInterceptor::DataWriter writer)
{
    unsigned int shutdowns = 0;
    try {
        using std::chrono::microseconds;
        microseconds::rep last_packet_ts = 0;
        microseconds::rep last_sent_ts = 0;

        while (shutdowns < 2) {
            const nets::DataPiece piece = decoder->next_tcp(connection_id);
            if (piece.is_connection_shutdown())
                ++shutdowns;

            if (last_packet_ts) {
                auto packet_gap = piece.timestamp - last_packet_ts;
                auto sent_gap = nets::get_microsecond_timestamp() - last_sent_ts;
                auto diff = static_cast<microseconds::rep>(packet_gap / speed_mul) - sent_gap;
                if (diff > 0)
                    std::this_thread::sleep_for(microseconds(diff));
            }
            last_packet_ts = piece.timestamp;
            last_sent_ts = nets::get_microsecond_timestamp();

            writer(piece);
        }
    } catch (NoMoreData&) {}
}


class ReplayingInterceptor : public nets::PipeInterceptor {
public:
    using ReplayManager = std::function<void(nets::ConnectionId, std::shared_ptr<TcpDecoder>, DataWriter)>;

private:
    std::shared_ptr<TcpDecoder> decoder;
    nets::ConnectionId connection_id;
    DataWriter writer;
    ReplayManager replayer;
    std::thread replay_thread;

public:
    ReplayingInterceptor(std::shared_ptr<TcpDecoder> decoder, const nets::ConnectionId& connectionId,
                         ReplayManager replay_manager)
        : decoder(std::move(decoder)), connection_id(connectionId), replayer(replay_manager)
    {}

    void set_writer(DataWriter w) override
    {
        writer = w;
        replay();
    }

    void put(const nets::DataPiece&) override
    {}

    ~ReplayingInterceptor() override
    {
        if (replay_thread.joinable())
            replay_thread.join();
    }

private:
    void replay()
    {
        replay_thread = std::thread{
            [this]() {
                try {
                    replayer(connection_id, decoder, writer);
                } catch (std::runtime_error&) {
                    logging::text("Replay interrupted by socket error");
                    // Try to shutdown connections
                    for (auto d : {nets::DataDirection::TO_CLIENT, nets::DataDirection::TO_SERVER})
                        try {
                            writer(nets::DataPiece{
                                .connection_id = connection_id,
                                .direction = d,
                                .data = ""
                            });
                        } catch (std::runtime_error&) {}
                }
            }
        };
    }
};


class TrafficController {
public:
    using SendCallable = std::function<void(nets::IPv4Packet&)>;
    using RecvCallable = std::function<nets::IPv4Packet(void)>;

private:
    using TcpDecoderPtr = std::shared_ptr<TcpDecoder>;
    using TcpEncoderPtr = std::shared_ptr<TcpEncoder>;

    bool replay_mode;
    ReplayingInterceptor::ReplayManager replay_manager;
    nets::Subnet client_subnet;

    time_machine::BlockingQueue<nets::IPv4Packet> service_queue{};
    std::shared_ptr<SocketPipeFactory> service;

    std::map<nets::ConnectionSideId, std::string> addr_repair_table;

    std::variant<TcpDecoderPtr, TcpEncoderPtr> tcp_coder;

public:
    TrafficController(const std::string& file, bool replay_mode,
                      nets::Subnet client_subnet, std::unique_ptr<SocketPipeFactory> spf)
        : replay_mode(replay_mode), client_subnet(client_subnet), service(std::move(spf))
    {
        if (replay_mode) {
            tcp_coder = std::make_shared<TcpDecoder>(file);
        } else {
            tcp_coder = std::make_shared<TcpEncoder>(file);
        }
        service->start_accepting_thread();
    }

    void set_replay_manager(ReplayingInterceptor::ReplayManager r_manager)
    {
        replay_manager = r_manager;
    }

    void process_traffic(RecvCallable in, SendCallable out)
    {
        try {
            while (true) {
                nets::IPv4Packet packet = in();
                packet.decrease_ttl();

                if (client_subnet.contains(packet.origin.address_only()))
                    process_from_users(std::move(packet), out);
                else
                    process_from_service(std::move(packet), out);
            }
        } catch (NoMoreData&) {
            logging::text("No more data!");
        } catch (time_machine::QueueClosed&) {}
    }

    ~TrafficController()
    {
        service_queue.close();
    }

private:
    void process_from_users(nets::IPv4Packet packet, SendCallable out)
    {
        if (!packet.is_tcp()) {
            logging::ip("Non-tcp:", packet);
            out(packet);
            return;
        } else {
            if (!packet.is_valid_tcp()) {
                logging::text("Corrupted TCP packet, dropping");
                return;
            }

            if (packet.is_tcp_handshake() && !packet.flag_ack()) {
                logging::tcp("From users (newpipe):", packet);
                addr_repair_table[packet.source_side()] = packet.destination_addr();

                nets::ConnectionId conn_id = {
                    .server_side = packet.destination_side(),
                    .client_addr = packet.source_addr()
                };
                service->request_new_pipe(conn_id, packet.tcp_sport(), create_interceptor(conn_id));
            } else {
                logging::tcp("From users:", packet);
            }
        }

        packet.set_destination(client_subnet.inverse().masquerade(packet.destination_addr()));
        service->send(packet);
    }

    void process_from_service(nets::IPv4Packet packet, SendCallable out)
    {
        if (packet.is_tcp()) {
            if (!packet.is_valid_tcp()) {
                logging::text("Corrupted TCP packet, dropping");
                return;
            }

            std::string from = addr_repair_table[packet.destination_side()];
            if (!from.empty())
                packet.set_source(from);

            logging::tcp("From service:", packet);
        } else {
            logging::ip("From service, non-tcp:", packet);
        }

        packet.set_source(client_subnet.masquerade(packet.source_addr()));
        out(packet);
    }

    std::shared_ptr<nets::PipeInterceptor> create_interceptor(const nets::ConnectionId conn_id)
    {
        if (replay_mode)
            return std::make_shared<ReplayingInterceptor>(std::get<TcpDecoderPtr>(tcp_coder), conn_id, replay_manager);
        else
            return std::make_shared<RecordingInterceptor>(std::get<TcpEncoderPtr>(tcp_coder), conn_id);
    }
};

} // namespace playground
