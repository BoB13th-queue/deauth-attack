#ifndef ASSOC_REQUEST_PACKET_H
#define ASSOC_REQUEST_PACKET_H

#include <cstdint>
#include <vector>
#include "mac.h"

namespace AssocConstants
{
    // Frame Control
    constexpr uint8_t FRAME_CTRL_SUBTYPE_ASSOC_REQ = 0x00; // Mgmt Subtype=0000 => Assoc Request
    constexpr uint8_t FRAME_CTRL_FLAGS = 0x00;

    // Duration
    constexpr uint16_t DEFAULT_DURATION = 0x013A;

    // Sequence Control
    constexpr uint16_t DEFAULT_SEQ_CTRL = 0x0000;

    // Association Request Body Defaults
    constexpr uint16_t DEFAULT_CAPABILITY = 0x0431; // ESS, Short Preamble 등 예시
    constexpr uint16_t DEFAULT_LISTEN_INT = 0x000A; // ex) 10
    // IE Tags
    constexpr uint8_t TAG_SSID = 0x00;
    constexpr uint8_t TAG_SUPPORTED_RATES = 0x01;
    // 간단 예시
    constexpr uint8_t RATE_1MBPS = 0x02; // 1 * 0.5Mbps
} // namespace AssocConstants

class AssocRequestPacket
{
public:
    AssocRequestPacket(const Mac &ap_mac, const Mac &st_mac)
        : version_type(AssocConstants::FRAME_CTRL_SUBTYPE_ASSOC_REQ),
          flags(AssocConstants::FRAME_CTRL_FLAGS),
          duration(AssocConstants::DEFAULT_DURATION),
          addr1(ap_mac),
          addr2(st_mac),
          addr3(ap_mac),
          seq_ctrl(AssocConstants::DEFAULT_SEQ_CTRL),
          capability(AssocConstants::DEFAULT_CAPABILITY),
          listen_interval(AssocConstants::DEFAULT_LISTEN_INT)
    {
    }

    std::vector<uint8_t> toBytes() const
    {
        std::vector<uint8_t> pkt;

        // 1) Frame Control (2바이트)
        pkt.push_back(version_type);
        pkt.push_back(flags);

        // 2) Duration (2바이트)
        pkt.push_back(static_cast<uint8_t>(duration & 0xff));
        pkt.push_back(static_cast<uint8_t>((duration >> 8) & 0xff));

        // 3) Address1 (AP MAC)
        for (auto b : addr1.toBytes())
            pkt.push_back(b);

        // 4) Address2 (Station MAC)
        for (auto b : addr2.toBytes())
            pkt.push_back(b);

        // 5) Address3 (BSSID)
        for (auto b : addr3.toBytes())
            pkt.push_back(b);

        // 6) Sequence Control (2바이트)
        pkt.push_back(static_cast<uint8_t>(seq_ctrl & 0xff));
        pkt.push_back(static_cast<uint8_t>((seq_ctrl >> 8) & 0xff));

        // 7) Association Request Body
        //    (a) Capability Info (2바이트)
        pkt.push_back(static_cast<uint8_t>(capability & 0xff));
        pkt.push_back(static_cast<uint8_t>((capability >> 8) & 0xff));

        //    (b) Listen Interval (2바이트)
        pkt.push_back(static_cast<uint8_t>(listen_interval & 0xff));
        pkt.push_back(static_cast<uint8_t>((listen_interval >> 8) & 0xff));

        //    (c) SSID Parameter Set
        pkt.push_back(AssocConstants::TAG_SSID); // Tag Number=0 (SSID)
        pkt.push_back(0x00);                     // Length=0 (빈 SSID)

        //    (d) Supported Rates
        pkt.push_back(AssocConstants::TAG_SUPPORTED_RATES); // Tag=1
        pkt.push_back(0x01);                                // Length=1
        pkt.push_back(AssocConstants::RATE_1MBPS);          // 1Mbps

        return pkt;
    }

private:
    // Frame Control
    uint8_t version_type;
    uint8_t flags;
    uint16_t duration;

    // 주소 필드
    Mac addr1; // AP MAC
    Mac addr2; // Station MAC
    Mac addr3; // AP MAC

    // 시퀀스 제어
    uint16_t seq_ctrl;

    // Association Request Body
    uint16_t capability;
    uint16_t listen_interval;
};

#endif // ASSOC_REQUEST_PACKET_H
