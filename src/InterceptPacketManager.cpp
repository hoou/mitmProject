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

    filter << "(";
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

    filter << ")";

    setListenFilterExpression(filter.str());
}

void InterceptPacketManager::processPacket(u_char *payload, size_t length) {
//    Packet packet(payload, length);
    cout << "from: " << Utils::ipv4ToString(*(from.getIpv4addresses().begin())) << endl;
    cout << "to: " << Utils::ipv4ToString(*(to.getIpv4addresses().begin())) << endl << endl;
}
