#include <sstream>
#include <iostream>
#include "InterceptPacketManager.h"
#include "IPv4_packet.h"
#include "IPv6_packet.h"

InterceptPacketManager::InterceptPacketManager(NetworkInterface &networkInterface, Host from, Host to)
        : PacketManager(networkInterface), from(from), to(to) {
    initFilters();
}

void InterceptPacketManager::initFilters() {
    stringstream filter;
    set<in6_addr> ipv6addresses;

    filter << "(ether src " << Utils::formatMacAddress(from.getMacAddress(), six_groups_of_two_hexa_digits_sep_colon)
           << ")";

    filter << " and ";
    filter << "(ether dst " << Utils::formatMacAddress(networkInterface.getHost()->getMacAddress(),
                                                       six_groups_of_two_hexa_digits_sep_colon) << ")";

    filter << " and ";
    filter << "( not (";

    filter << InterceptPacketManager::createDstFilter(networkInterface.getHost()->getIpv4addresses());

    if (networkInterface.getHost()->getIpv6addresses().size() > 0) {
        filter << " or ";
        filter << InterceptPacketManager::createDstFilter(networkInterface.getHost()->getIpv6addresses());
    }
    filter << "))";

    cout << filter.str() << endl;

    setListenFilterExpression(filter.str());
}

void InterceptPacketManager::processPacket(u_char *payload, size_t length) {
    Packet packet(payload, length);
    packet.setEthernetSourceAddress(networkInterface.getHost()->getMacAddress());
    packet.setEthernetDestinationAddress(to.getMacAddress());
    send(&packet);

//    cout << "from: " << Utils::ipv4ToString(*(from.getIpv4addresses().begin())) << endl;
//    cout << "to: " << Utils::ipv4ToString(*(to.getIpv4addresses().begin())) << endl;
//    cout << "size: " << length << endl << endl;
}
