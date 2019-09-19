#include <memory>

#pragma once

#include <map>
#include <variant>
#include <chrono>
#include <fstream>

#include "nets.hpp"
#include "bqueue.hpp"
#include "logging.hpp"



namespace playground {

class NoMoreData : public std::runtime_error {
public:
    NoMoreData()
        : runtime_error("No more data")
    {}
};


class IpEncoder {
private:
    std::ofstream file;

public:
    IpEncoder() = default;

    explicit IpEncoder(const std::string& path)
        : file(path)
    {}

    void write_next(const nets::IPv4Packet& packet)
    {
        using std::chrono::microseconds;
        using std::chrono::system_clock;
        using std::chrono::duration_cast;
        microseconds::rep us = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();

        file << us << '\n';
        file << packet.length() << '\n';
        file.write(packet.raw_bytes(), packet.length());
    }
};


class IpDecoder {
private:
    std::ifstream file;

public:
    IpDecoder() = default;

    explicit IpDecoder(const std::string& path)
        : file(path)
    {}

    nets::IPv4Packet read_next()
    {
        using std::chrono::microseconds;
        using std::chrono::system_clock;
        using std::chrono::duration_cast;
        microseconds::rep us;
        size_t len;

        file >> us >> len;
        if (file.fail()) {
            throw NoMoreData{};
        }

        std::string dummy;
        std::getline(file, dummy);

        char* data = new char[len];
        file.read(data, len);
        nets::IPv4Packet packet = {data};
        delete[] data;

        if (file.fail()) {
            throw NoMoreData{};
        }

        return packet;
    }
};


class TcpEncoder {
private:
    std::ofstream file;
    std::mutex lock;

public:
    TcpEncoder() = default;

    explicit TcpEncoder(const std::string& path)
        : file(path)
    {}

    void write_next(const nets::DataPiece& piece)
    {
        std::lock_guard guard(lock);

        using std::chrono::microseconds;
        using std::chrono::system_clock;
        using std::chrono::duration_cast;
        microseconds::rep us = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();

        file << us << ' ' << piece.data.length() << ' ';
        file << piece.connection_id << ' ' << piece.direction << '\n';
        file.write(piece.data.data(), piece.data.length());
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
        using std::chrono::microseconds;
        using std::chrono::system_clock;
        using std::chrono::duration_cast;

        microseconds::rep us;
        size_t len;
        nets::DataPiece piece;

        file >> us >> len >> piece.connection_id >> piece.direction;
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
        logging::text("Got piece");
        encoder->write_next(piece);
        writer(piece);
    }
};


class ReplayingInterceptor : public nets::PipeInterceptor {
private:
    std::shared_ptr<TcpDecoder> decoder;
    nets::ConnectionId connection_id;
    DataWriter writer;

public:
    ReplayingInterceptor(const std::shared_ptr<TcpDecoder>& decoder, const nets::ConnectionId& connectionId)
        : decoder(decoder), connection_id(connectionId)
    {}

    void set_writer(DataWriter w) override
    {
        writer = w;
        replay();
    }

    void put(const nets::DataPiece&) override
    {}

private:
    void replay() {
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
};


class TrafficController {
public:
    using SendCallable = std::function<void(nets::IPv4Packet&)>;
    using RecvCallable = std::function<nets::IPv4Packet(void)>;

private:
    using TcpDecoderPtr = std::shared_ptr<TcpDecoder>;
    using TcpEncoderPtr = std::shared_ptr<TcpEncoder>;

    bool replay_mode;

    time_machine::BlockingQueue<nets::IPv4Packet> service_queue{};
    SocketPipeFactory service{};

    std::mutex reptable_lock;
    std::map<nets::ConnectionSideId, std::string> addr_repair_table;

    std::variant<TcpDecoderPtr, TcpEncoderPtr> tcp_coder;

public:
    TrafficController(const std::string& file, bool replay_mode)
        : replay_mode(replay_mode)
    {
        service.assign_addresses();

        if (replay_mode) {
            tcp_coder = std::make_shared<TcpDecoder>(file);
        } else {
            tcp_coder = std::make_shared<TcpEncoder>(file);
        }
        service.serve(service_queue);
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"

    void process_traffic(RecvCallable in, SendCallable out)
    {
        std::thread{
            [this, out]() {
                nets::IPv4Packet packet;
                while (service_queue.get(packet)) {
                    packet.decrease_ttl();

                    if (packet.is_tcp()) {
                        std::lock_guard lock(reptable_lock);

                        std::string from = addr_repair_table[packet.destination_side()];
                        if (!from.empty())
                            packet.set_source(from);

                        logging::tcp("From service:", packet);
                    } else {
                        logging::ip("From service, non-tcp:", packet);
                    }

                    out(packet);
                }
            }
        }.detach();

        try {
            std::future<std::shared_ptr<nets::SocketPipe>> wait_for_pipe_init;
            while (true) {
                nets::IPv4Packet packet = in();
                packet.decrease_ttl();

                if (!packet.is_tcp()) {
                    logging::ip("Non-tcp:", packet);
                    out(packet);
                    continue;
                } else {
                    if (packet.source_addr() == "10.0.0.254") {
                        // routing shit
                        logging::tcp("Routing shit:", packet);
                        continue;
                    }

                    if (packet.is_tcp_handshake() && !packet.flag_ack()) {
                        logging::tcp("From users (newpipe):", packet);
                        {
                            std::lock_guard lock(reptable_lock);
                            addr_repair_table[packet.source_side()] = packet.destination_addr();
                        }

                        nets::ConnectionId conn_id = {
                            .server_side = packet.destination_side(),
                            .client_addr = packet.source_addr()
                        };
                        service.request_new_pipe(conn_id, packet.tcp_sport(), create_interceptor(conn_id));
                    } else {
                        logging::tcp("From users:", packet);
                    }
                }

                packet.set_destination("10.0.0.254");
                service.send(packet);
            }
        } catch (NoMoreData&) {
            std::cerr << "No more data!" << std::endl;
        } catch (time_machine::QueueClosed&) {}
    }

#pragma clang diagnostic pop

private:
    std::shared_ptr<nets::PipeInterceptor> create_interceptor(const nets::ConnectionId conn_id)
    {
        if (replay_mode)
            return std::make_shared<ReplayingInterceptor>(std::get<TcpDecoderPtr>(tcp_coder), conn_id);
        else
            return std::make_shared<RecordingInterceptor>(std::get<TcpEncoderPtr>(tcp_coder), conn_id);
    }
};


}
