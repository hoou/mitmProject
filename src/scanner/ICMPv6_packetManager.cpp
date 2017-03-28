#include <iostream>
#include "ICMPv6_packetManager.h"

ICMPv6_packetManager *ICMPv6_packetManager::instance = nullptr;

ICMPv6_packetManager::ICMPv6_packetManager() {}

void ICMPv6_packetManager::processPacket(u_char *payload, size_t length) {
    ICMPv6_packet *packet = new ICMPv6_packet(payload, length);

    caughtPackets.push_back(packet);
}

ICMPv6_packetManager *ICMPv6_packetManager::getInstance() {
    if (instance == nullptr) {
        instance = new ICMPv6_packetManager();
        instance->setListenFilterExpression("icmp6");
    }
    return instance;
}

void ICMPv6_packetManager::clean() {
    PacketManager::clean();

    for (auto &packet : caughtPackets) {
        delete (packet);
    }

    if (instance != nullptr)
        delete instance;
}

const vector<ICMPv6_packet *> &ICMPv6_packetManager::getCaughtPackets() const {
    return caughtPackets;
}
