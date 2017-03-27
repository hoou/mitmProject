#include <pcap.h>
#include <stdexcept>
#include <iostream>
#include "ARP_packetManager.h"

ARP_packetManager *ARP_packetManager::instance = nullptr;

ARP_packetManager::ARP_packetManager() {}

vector<ARP_packet *> &ARP_packetManager::getCaughtARP_packets() {
    return caughtArpPackets;
}

void ARP_packetManager::setupFilters() {
    int status;
    string filterExpression;
    struct bpf_program filter;

    //    filterExpression = "arp and dst net " + string(inet_ntoa(networkInterface->getAddress()));
    filterExpression = "arp";

    status = pcap_compile(listenPCAP_handle, &filter, filterExpression.c_str(), 0, 0);
    if (status == -1)
        throw runtime_error(pcap_geterr(listenPCAP_handle));

    status = pcap_setfilter(listenPCAP_handle, &filter);
    if (status == -1)
        throw runtime_error(pcap_geterr(listenPCAP_handle));

    pcap_freecode(&filter);
}

void ARP_packetManager::processPacket(u_char *payload) {
    ARP_packet *arp_packet = new ARP_packet(payload, ETH_HLEN + sizeof(struct ether_arp));

    caughtArpPackets.push_back(arp_packet);
}

ARP_packetManager *ARP_packetManager::getInstance() {
    if (instance == nullptr) {
        instance = new ARP_packetManager();
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
