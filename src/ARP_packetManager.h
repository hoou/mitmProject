#ifndef PROJEKT_NEW_ARPPACKETMANAGER_H
#define PROJEKT_NEW_ARPPACKETMANAGER_H

#include <string>
#include <thread>
#include <pcap.h>
#include <mutex>
#include <map>
#include "ARP_packet.h"
#include "NetworkInterface.h"
#include "PacketManager.h"

using namespace std;

class ARP_packetManager : public PacketManager {
private:
    static ARP_packetManager *instance;

    vector<ARP_packet*> caughtArpPackets;

    ARP_packetManager();

    void processPacket(u_char *payload, size_t length) override;

public:
    static ARP_packetManager *getInstance();

    void clean() override;

    vector<ARP_packet *> &getCaughtARP_packets();
};


#endif //PROJEKT_NEW_ARPPACKETMANAGER_H
