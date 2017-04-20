#include <sstream>
#include <iostream>
#include "InterceptPacketManager.h"

InterceptPacketManager::InterceptPacketManager(NetworkInterface &networkInterface, Host from, Host to)
        : PacketManager(networkInterface), from(from), to(to) {
    initFilters();
}

void InterceptPacketManager::initFilters() {
    stringstream filter;
    set<in6_addr> ipv6addresses;

    filter << "(ether src " << Utils::formatMacAddress(from.getMacAddress(), six_groups_of_two_hexa_digits_sep_colon)
           << ")";

//    filter << " and ";
//    filter << "(ether dst " << Utils::formatMacAddress(networkInterface.getHost()->getMacAddress(),
//                                                       six_groups_of_two_hexa_digits_sep_colon) << ")";

    filter << " and ";
    filter << "( not (";

    filter << InterceptPacketManager::createDstFilter(networkInterface.getHost()->getIpv4addresses());

    if (networkInterface.getHost()->getIpv6addresses().size() > 0) {
        filter << " or ";
        filter << InterceptPacketManager::createDstFilter(networkInterface.getHost()->getIpv6addresses());
    }
    filter << "))";

    setListenFilterExpression(filter.str());
}

void InterceptPacketManager::processPacket(u_char *payload, size_t length) {
    Packet packet(payload, length);
    packet.setEthernetSourceAddress(networkInterface.getHost()->getMacAddress());
    packet.setEthernetDestinationAddress(to.getMacAddress());
    send(&packet);
}
