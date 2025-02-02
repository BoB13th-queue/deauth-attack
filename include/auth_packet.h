#ifndef AUTH_PACKET_H
#define AUTH_PACKET_H

#include <cstdint>
#include <vector>
#include "mac.h"

// Frame Control
constexpr uint8_t FRAME_CTRL_SUBTYPE_AUTH = 0xB0; // Type=Mgmt(0), Subtype=Auth(1011 => 0xB)
constexpr uint8_t FRAME_CTRL_FLAGS = 0x00;        // To DS/From DS 등 플래그 없음

// Duration
constexpr uint16_t DEFAULT_DURATION = 0x013A; // 임의로 314µs

// Sequence Control
constexpr uint16_t DEFAULT_SEQ_CTRL = 0x0000; // Fragment=0, Sequence=0

// Authentication Body
constexpr uint16_t AUTH_ALGO_OPEN_SYSTEM = 0x0000; // Open System = 0
constexpr uint16_t AUTH_SEQ_FIRST = 0x0001;        // 첫 번째 메시지
constexpr uint16_t AUTH_STATUS_SUCCESS = 0x0000;   // 요청 시 0

class AuthPacket
{
public:
    AuthPacket(const Mac &ap_mac, const Mac &st_mac)
        : version_type(FRAME_CTRL_SUBTYPE_AUTH),
          flags(FRAME_CTRL_FLAGS),
          duration(DEFAULT_DURATION),
          addr1(st_mac),
          addr2(ap_mac),
          addr3(ap_mac),
          seq_ctrl(DEFAULT_SEQ_CTRL),
          auth_algo(AUTH_ALGO_OPEN_SYSTEM),
          auth_seq(AUTH_SEQ_FIRST),
          status_code(AUTH_STATUS_SUCCESS)
    {
    }

    std::vector<uint8_t> toBytes() const
    {
        std::vector<uint8_t> pkt;

        // 1) Frame Control (2바이트)
        pkt.push_back(version_type);
        pkt.push_back(flags);

        // 2) Duration (2바이트, 리틀 엔디안)
        pkt.push_back(static_cast<uint8_t>(duration & 0xff));
        pkt.push_back(static_cast<uint8_t>((duration >> 8) & 0xff));

        // 3) Address1 (AP MAC)
        for (auto b : addr1.toBytes())
            pkt.push_back(b);

        // 4) Address2 (Station MAC)
        for (auto b : addr2.toBytes())
            pkt.push_back(b);

        // 5) Address3 (BSSID = AP MAC)
        for (auto b : addr3.toBytes())
            pkt.push_back(b);

        // 6) Sequence Control (2바이트)
        pkt.push_back(static_cast<uint8_t>(seq_ctrl & 0xff));
        pkt.push_back(static_cast<uint8_t>((seq_ctrl >> 8) & 0xff));

        // 7) Authentication Management Body (6바이트)
        //   - Auth Algorithm (2바이트)
        pkt.push_back(static_cast<uint8_t>(auth_algo & 0xff));
        pkt.push_back(static_cast<uint8_t>((auth_algo >> 8) & 0xff));
        //   - Auth Sequence (2바이트)
        pkt.push_back(static_cast<uint8_t>(auth_seq & 0xff));
        pkt.push_back(static_cast<uint8_t>((auth_seq >> 8) & 0xff));
        //   - Status Code (2바이트)
        pkt.push_back(static_cast<uint8_t>(status_code & 0xff));
        pkt.push_back(static_cast<uint8_t>((status_code >> 8) & 0xff));

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

    // Authentication Body
    uint16_t auth_algo;
    uint16_t auth_seq;
    uint16_t status_code;
};

#endif // AUTH_PACKET_H
