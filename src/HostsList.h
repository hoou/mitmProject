#ifndef PROJEKT_NEW_HOSTSLIST_H
#define PROJEKT_NEW_HOSTSLIST_H

#include <vector>
#include <map>
#include <set>
#include "ARP_packet.h"
#include "ICMPv6_packet.h"
#include "Host.h"

class HostsList {
private:
    set<Host> hosts;

public:
    HostsList();

    HostsList(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets);

    set<Host>::iterator find(mac_addr address);

    void insert(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets);

    void remove(mac_addr address);

    void exportToXML(string filename);
};


#endif //PROJEKT_NEW_HOSTSLIST_H
