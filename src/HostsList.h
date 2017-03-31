#ifndef PROJEKT_NEW_HOSTSLIST_H
#define PROJEKT_NEW_HOSTSLIST_H

#include <vector>
#include <map>
#include <set>
#include "ARP_packet.h"
#include "ICMPv6_packet.h"

class HostsList {
private:
    map<mac_addr, pair<vector<in_addr>, set<in6_addr>>> macAddressMap;

public:
    HostsList();

    HostsList(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets);

    void insert(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets);

    void remove(mac_addr address);

    void exportToXML(string filename);
};


#endif //PROJEKT_NEW_HOSTSLIST_H
