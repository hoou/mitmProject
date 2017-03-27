#include <pcap.h>
#include <stdexcept>
#include <iostream>
#include "ARP_packetManager.h"

ARP_packetManager *ARP_packetManager::instance = nullptr;

ARP_packetManager::ARP_packetManager() {}

vector<ARP_packet *> &ARP_packetManager::getCaughtARP_packets() {
    return caughtArpPackets;
}

void ARP_packetManager::processPacket(u_char *payload, size_t length) {
    ARP_packet *arp_packet = new ARP_packet(payload, length);

    caughtArpPackets.push_back(arp_packet);
}

ARP_packetManager *ARP_packetManager::getInstance() {
    if (instance == nullptr) {
        instance = new ARP_packetManager();
        instance->setListenFilterExpression("arp");
    }
    return instance;
}

void ARP_packetManager::clean() {
    PacketManager::clean();

    for (auto &packet : caughtArpPackets) {
        delete (packet);
    }

    if (instance != nullptr)
        delete instance;
}
