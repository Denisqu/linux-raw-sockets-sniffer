#include <iostream>
#include <string>
#include <optional>
#include <string_view>
#include <memory>

#include "socket_sniffer.h"

namespace {
    using namespace sniffer;

    const char* stringify(Protocol val) {
        switch (val) {
            case Protocol::TCP:
                return "tcp";
            case Protocol::UDP:
                return "udp";
            case Protocol::ARP:
                return "arp";
            case Protocol::ICMP:
                return "icmp";
            default:
                return "";
        }
    }

    std::optional<Protocol> parse(const std::string_view val) {
        if (val == stringify(Protocol::TCP)) {
            return Protocol::TCP;
        } else if (val == stringify(Protocol::UDP)) {
            return Protocol::UDP;
        } else if (val == stringify(Protocol::ICMP)) {
            return Protocol::ICMP;
        } else if (val == stringify(Protocol::ARP)) {
            return Protocol::ARP;
        }

        return {};
    }

    std::optional<Protocol> parseArguments(const int count, const auto& arguments) {
        if (count != 2) {
            return {};
        }

        return parse(arguments[1]);
    }

    void verifySelectedProtocol(const auto val, const auto argc, const auto argv) {
        if(!val.has_value()) {
            const auto getStringOfOptions = [](int count, const auto& options) {
                std::string result{};
                for(int i = 0; i < count; ++i) {
                    result += options[i];
                    result += " ";
                }
                return result;
            };
            std::cout << "Error, invalid command line options. Used options: "
                      << getStringOfOptions(argc, argv) << std::endl;
            abort();
        }

        std::cout << "Selected protocol: " << stringify(val.value()) << std::endl;
    }
}

int main(int argc, char* argv[]) {
    // Parse input
    const auto selectedProtocol = parseArguments(argc, argv);
    verifySelectedProtocol(selectedProtocol, argc, argv);

    auto sniffer = std::make_unique<sniffer::socket_sniffer>(selectedProtocol.value());
    const auto initStatus = sniffer->init();
    if (std::holds_alternative<std::string>(initStatus)) {
        std::cout << std::get<std::string>(initStatus);
        abort();
    }
    sniffer->start();
    return 0;
}
