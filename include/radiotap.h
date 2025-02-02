#ifndef RADIOTAP_HEADER_H
#define RADIOTAP_HEADER_H

#include <cstdint>
#include <vector>

class RadiotapHeader {
public:
    // Radiotap 고정 필드
    uint8_t  it_version; // 버전
    uint8_t  it_pad;     // 패딩(일반적으로 0)
    uint16_t it_len;     // 전체 Radiotap 헤더 길이 (리틀 엔디안)
    uint32_t it_present; // 어떤 필드를 포함하는지 표시

    // 여기서는 Flags(1바이트) + [1바이트 정렬 패딩] + TxFlags(2바이트)만 포함 예시
    uint8_t  flags;      
    uint8_t  alignment_pad; // tx_flags를 2바이트 경계에 맞추기 위한 1바이트 패딩
    uint16_t tx_flags;

    // 기본 생성자
    RadiotapHeader() {
        // 1) Radiotap 기본값
        it_version = 0x00;
        it_pad     = 0x00;

        // 2) 실제 직렬화 시 12바이트가 되도록 설정
        //    (8바이트 기본 + flags(1B) + alignment_pad(1B) + tx_flags(2B) = 12)
        it_len     = 0x000c; 

        // 3) it_present = Flags(bit1) + TxFlags(bit15)
        //    bit1 → 0x00000002, bit15 → 0x00008000 → 합치면 0x00008002
        it_present = 0x00008002;

        flags          = 0x02;   // 예) short preamble
        alignment_pad  = 0x00;   // 항상 0으로 채워도 됨
        tx_flags       = 0x0000; // TxFlags 관련 설정값
    }

    // 바이트 벡터로 직렬화
    std::vector<uint8_t> toBytes() const {
        std::vector<uint8_t> bytes;
        bytes.reserve(it_len); 
        // (필드가 확실히 12바이트로 떨어지므로 reserve에 it_len 사용)

        // 1) it_version (1바이트)
        bytes.push_back(it_version);

        // 2) it_pad (1바이트)
        bytes.push_back(it_pad);

        // 3) it_len (2바이트, 리틀 엔디안)
        bytes.push_back(static_cast<uint8_t>( it_len       & 0xff));
        bytes.push_back(static_cast<uint8_t>((it_len >> 8) & 0xff));

        // 4) it_present (4바이트, 리틀 엔디안)
        bytes.push_back(static_cast<uint8_t>( it_present        & 0xff));
        bytes.push_back(static_cast<uint8_t>((it_present >> 8)  & 0xff));
        bytes.push_back(static_cast<uint8_t>((it_present >> 16) & 0xff));
        bytes.push_back(static_cast<uint8_t>((it_present >> 24) & 0xff));

        // 5) flags (1바이트)
        bytes.push_back(flags);

        // 6) alignment_pad (1바이트)
        bytes.push_back(alignment_pad);

        // 7) tx_flags (2바이트, 리틀 엔디안)
        bytes.push_back(static_cast<uint8_t>( tx_flags       & 0xff));
        bytes.push_back(static_cast<uint8_t>((tx_flags >> 8) & 0xff));

        return bytes;
    }
};

#endif // RADIOTAP_HEADER_H
