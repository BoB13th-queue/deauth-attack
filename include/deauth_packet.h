#ifndef DEAUTH_PACKET_H
#define DEAUTH_PACKET_H

#include <iostream>
#include <vector>
#include <pcap.h>
#include "mac.h"

using namespace std;

const uint8_t DEAUTH_TYPE = 0xC0;
const uint8_t DEAUTH_REASON_CODE = 0x07; //	Class 3 frame received from nonassociated STA (연결되지 않은 STA가 Class 3 프레임을 전송함)
const uint16_t DURATION = 0x013A;
const uint16_t FRAG_SEQ_NUM = 0x0000;

class DeauthPacket
{
public:
    DeauthPacket(const Mac &ap_mac, const Mac &st_mac)
        : type(DEAUTH_TYPE), flags(0x00), duration(DURATION), dest_mac(st_mac), src_mac(ap_mac), bssid(ap_mac),
          frag_seq_num(FRAG_SEQ_NUM), reason_code(DEAUTH_REASON_CODE) {}

    vector<uint8_t> toBytes() const
    {
        vector<uint8_t> bytes;
        bytes.push_back(type);
        bytes.push_back(flags);
        bytes.push_back(duration & 0xFF);
        bytes.push_back(duration >> 8);

        vector<uint8_t> destBytes = dest_mac.toBytes();
        bytes.insert(bytes.end(), destBytes.begin(), destBytes.end());

        vector<uint8_t> srcBytes = src_mac.toBytes();
        bytes.insert(bytes.end(), srcBytes.begin(), srcBytes.end());

        vector<uint8_t> bssidBytes = bssid.toBytes();
        bytes.insert(bytes.end(), bssidBytes.begin(), bssidBytes.end());

        bytes.push_back(frag_seq_num & 0xFF);
        bytes.push_back(frag_seq_num >> 8);
        bytes.push_back(reason_code & 0xFF);
        bytes.push_back(reason_code >> 8);

        return bytes;
    }

private:
    uint8_t type;
    uint8_t flags;
    uint16_t duration;
    Mac dest_mac;
    Mac src_mac;
    Mac bssid;
    uint16_t frag_seq_num;
    uint16_t reason_code;
};

#endif // DEAUTH_PACKET_H
