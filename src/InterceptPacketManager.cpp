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

    filter << "(not (ether src "
           << Utils::formatMacAddress(networkInterface.getPhysicalAddress(), six_groups_of_two_hexa_digits_sep_colon)
           << ")) and ((";
    filter << InterceptPacketManager::createSrcFilter(from.getIpv4addresses());
    ipv6addresses = from.getIpv6addresses();

    if (ipv6addresses.size() > 0) {
        filter << " or ";
        filter << InterceptPacketManager::createSrcFilter(ipv6addresses);
    }

    filter << ")";
    filter << " and ";
    filter << "(";

    filter << InterceptPacketManager::createDstFilter(to.getIpv4addresses());
    ipv6addresses = to.getIpv6addresses();
    if (ipv6addresses.size() > 0) {
        filter << " or ";
        filter << InterceptPacketManager::createDstFilter(ipv6addresses);
    }

    filter << "))";

    setListenFilterExpression(filter.str());
}

void InterceptPacketManager::processPacket(u_char *payload, size_t length) {
    Packet caughtPacket(payload, length);
    Packet modifiedPacket(caughtPacket.getType(), networkInterface.getPhysicalAddress(), to.getMacAddress());
    send(&modifiedPacket);

//    cout << "from: " << Utils::ipv4ToString(*(from.getIpv4addresses().begin())) << endl;
//    cout << "to: " << Utils::ipv4ToString(*(to.getIpv4addresses().begin())) << endl;
//    cout << "size: " << length << endl << endl;
}
