#ifndef PROJEKT_NEW_HOSTSLIST_H
#define PROJEKT_NEW_HOSTSLIST_H

#include <vector>
#include <map>
#include <set>
#include <libxml/parser.h>
#include "ARP_packet.h"
#include "ICMPv6_packet.h"
#include "Host.h"

class HostsList {
private:
    set<Host> hosts;

    /**
     * http://www.xmlsoft.org/examples/tree1.c
     *
     * Prints the names of the all the xml elements that are siblings or children of a given xml node.
     *
     * @param a_node the initial xml node to consider.
     */
    void print_element_names(xmlNode *a_node);

public:
    HostsList();

    HostsList(string filename);

    HostsList(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets);

    set<Host>::iterator find(mac_addr address);

    void insert(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets);

    void remove(mac_addr address);

    void exportToXML(string filename);

    void importFromXML(string filename);

    const set<Host> &getHosts() const;
};


#endif //PROJEKT_NEW_HOSTSLIST_H
