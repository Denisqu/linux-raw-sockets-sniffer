#ifndef RAW_SOCKET_SNIFFER_SOCKET_SNIFFER_H
#define RAW_SOCKET_SNIFFER_SOCKET_SNIFFER_H

#include <variant>
#include <string>
#include <memory>

namespace sniffer {

enum class Protocol {
    TCP,
    UDP,
    ARP,
    ICMP,
    Invalid
};

class socket_sniffer
{
public:
    explicit socket_sniffer(Protocol sniffedProtocol);
    std::variant<bool, std::string> init();
    void start();
    void stop();

private:
    void processPacket(const unsigned int size);

    Protocol m_selectedProtocol = Protocol::Invalid;
    int m_socket = -1;
    std::unique_ptr<uint8_t > m_buffer = nullptr;
    uint64_t m_receivedPackets = 0;
};

} // namespace sniffer

#endif // RAW_SOCKET_SNIFFER_SOCKET_SNIFFER_H
