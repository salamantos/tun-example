#include <iostream>

#include "isolation.hpp"
#include "bqueue.hpp"
#include "logging.hpp"
#include "traffic.hpp"
#include "CLI11.hpp"



int main(int argc, char* argv[])
{
    CLI::App app{"Net Playground"};

    std::string filename;
    std::string subnet_str;
    nets::Subnet client_subnet;
    bool replay, flood_replay;
    double replay_speed_mul = 1.0;
    int child_kill_signal;

    uid_t exec_uid = getuid();
    gid_t exec_gid = getgid();

    app.add_option("--subnet,-s", subnet_str, "Subnet")
        ->required();
    app.add_flag("--replay{true},--record{false}", replay, "Operation mode")
        ->required();
    app.add_option("--uid,-u", exec_uid, "User id to execute commands");
    app.add_option("--gid,-g", exec_gid, "Group id to execute commands");
    auto speed_opt = app.add_option("--speed", replay_speed_mul, "Replay speed multiplier")
        ->check(CLI::Range(0.0, std::numeric_limits<decltype(replay_speed_mul)>::infinity()));
    auto flood_opt = app.add_flag("--flood", flood_replay, "Use flood replay mode instead of time based")
        ->excludes(speed_opt);
    app.add_option("--file,-f", filename, "File to read/write traffic")
        ->default_val("test.traffic");
    app.add_option("--kill,-k", child_kill_signal, "Signal to kill child processes on termination. Default: SIGTERM")
        ->default_val("15");
    app.add_flag_callback("--nolog", []() {
        playground::logging::set_packet_logging_enabled(false);
    }, "Disable packet logging");

    app.allow_extras();
    try {
        app.parse(argc, argv);
        if (!replay) {
            if (!speed_opt->empty())
                throw CLI::RequiresError("--speed", "--replay");
            if (!flood_opt->empty())
                throw CLI::RequiresError("--flood", "--replay");
        }
    } catch (const CLI::ParseError& e) {
        return (app).exit(e);
    }

    client_subnet = nets::Subnet{subnet_str};
    auto commands = app.remaining();
    if (commands.size() + 2 > ~client_subnet.get_mask() + 1) {
        std::cerr << "Two many commands for specified subnet size" << std::endl;
        return 1;
    }
    if (commands.empty()) {
        std::cerr << "Specify at least one command after arguments" << std::endl;
        return 1;
    }

    if (disable_interrupting_signals())
        throw std::runtime_error("Problems with signals");

    multiplexing::MultiplexedWritingProvider<nets::IPv4Packet> tun_provider{
        [](const auto& packet) {
            return std::make_pair(packet.raw_bytes(), packet.length());
        }
    };
    std::vector<std::shared_ptr<playground::NetContainer>> containers;
    std::vector<playground::Process> user_processes;
    for (size_t i = 0; i < commands.size(); ++i) {
        const auto& cmd = commands[i];
        containers.emplace_back(new playground::NetContainer(client_subnet[i + 1], tun_provider))
            ->assign_addresses();
        try {
            user_processes.emplace_back(cmd, exec_uid, exec_gid, child_kill_signal);
        } catch (const std::runtime_error& err) {
            std::cerr << err.what() << std::endl;
        }
    }

    auto spf = std::make_shared<playground::SocketPipeFactory>(client_subnet.inverse(), tun_provider);
    spf->assign_addresses();

    playground::TrafficController tc{filename, replay, client_subnet, spf};
    if (replay) {
        if (flood_replay)
            tc.set_replay_manager(playground::simple_replayer);
        else
            tc.set_replay_manager([replay_speed_mul](auto a, auto b, auto c) {
                playground::time_based_replayer(replay_speed_mul, a, b, c);
            });
    }

    auto packet_handler = [&tc, &containers](nets::IPv4Packet&& packet) {
        tc.process_packet([&containers](nets::IPv4Packet&& packet) {
            for (auto container : containers) {
                auto p = packet;
                container->send(std::move(p));
            }
        }, std::move(packet));
    };

    for (auto container : containers)
        container->serve(packet_handler);
    spf->serve(packet_handler);

    std::atomic_bool stopped{false};
    auto tunnel_read_thread = std::thread{
        [&tun_provider, &stopped]() {
            try {
                while (!stopped.load(std::memory_order_relaxed)) {
                    tun_provider.wait();
                }
            } catch (time_machine::QueueClosed&) {}
        }
    };

    wait_interrupting_signals();
    playground::logging::text("Stopping");

    stopped.store(true, std::memory_order_relaxed);
    tun_provider.interrupt();

    tunnel_read_thread.join();
    return 0;
}
