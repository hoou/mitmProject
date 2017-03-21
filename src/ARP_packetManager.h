#ifndef PROJEKT_NEW_ARPPACKETMANAGER_H
#define PROJEKT_NEW_ARPPACKETMANAGER_H

#include <string>
#include <thread>
#include <pcap.h>
#include <mutex>
#include <map>
#include "ARP_packet.h"
#include "NetworkInterface.h"

using namespace std;

class ARP_packetManager {
private:
    static mutex mtx;
    static NetworkInterface *networkInterface;
    static thread listenThread;
    static pcap_t *listenPCAP_handle;
    static pcap_t *sendPCAP_handle;
    static vector<ARP_packet> caughtARPpackets;

    static void listenTask();

    static void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

    ARP_packetManager();

public:

    static void init(NetworkInterface *networkInterface);

    static void clean();

    static void listen();

    static void stopListen();

    static void wait();

    static void sendRequest(ARP_packet arpPacket);

    static const vector<ARP_packet> &getCaughtARP_packets();

    static const map<string, vector<in_addr>> getMACaddressMap();
};


#endif //PROJEKT_NEW_ARPPACKETMANAGER_H
