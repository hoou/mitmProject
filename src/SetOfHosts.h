#ifndef PDS_MITM_HOSTSLIST_H
#define PDS_MITM_HOSTSLIST_H

#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <libxml/parser.h>
#include "ARP_packet.h"
#include "ICMPv6_packet.h"
#include "Host.h"
#include "Group.h"

/**
 * Set of network hosts
 */
class SetOfHosts {
private:
    set<Host> hosts;

public:
    /**
     * Construct empty set of hosts
     */
    SetOfHosts();

    /**
     * Construct set of hosts from given XML
     * @param filename of XML
     */
    SetOfHosts(string filename);

    /**
     * Construct set of hosts from given ARP and ICMPv6 packets
     * @param arpPackets
     * @param icmpv6Packets
     */
    SetOfHosts(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets);

    /**
     * Find host in set by given MAC address
     * @param address MAC address to search for
     * @return found host with given MAC address
     */
    set<Host>::iterator find(mac_addr address);

    /**
     * Construct set of Groups from hosts included in this set
     * @return
     */
    set<Group> getGroups();

    /**
     * Check if every group in given set has exactly two hosts
     * @param groups
     * @return true if every group in given set has exactly two hosts, false otherwise
     */
    static bool hasEveryGroupExactlyTwoHosts(set<Group> groups);

    /**
     * Insert new hosts to set from given ARP and ICMPv6 packets
     * @param arpPackets
     * @param icmpv6Packets
     */
    void insert(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets);

    /**
     * Remove host from set by given MAC address
     * @param address MAC address to search for
     */
    void remove(mac_addr address);

    /**
     * Export set of hosts to XML
     * @param filename name of XML
     */
    void exportToXML(string filename);

    /**
     * Import set of hosts from XML
     * @param filename name of XML
     */
    void importFromXML(string filename);

    const set<Host> &getHosts() const;
};


#endif //PDS_MITM_HOSTSLIST_H
