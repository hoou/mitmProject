#ifndef PROJEKT_NEW_HOSTSLIST_H
#define PROJEKT_NEW_HOSTSLIST_H

#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <libxml/parser.h>
#include "ARP_packet.h"
#include "ICMPv6_packet.h"
#include "Host.h"
#include "Group.h"

class HostsList {
private:
    set<Host> hosts;

public:
    HostsList();

    HostsList(string filename);

    HostsList(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets);

    set<Host>::iterator find(mac_addr address);

    set<Group> getGroups();

    static bool hasEveryGroupExactlyTwoHosts(set<Group> groups);

    void insert(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets);

    void remove(mac_addr address);

    void exportToXML(string filename);

    void importFromXML(string filename);

    const set<Host> &getHosts() const;
};


#endif //PROJEKT_NEW_HOSTSLIST_H
