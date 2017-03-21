#ifndef PROJEKT_NEW_HOSTSLIST_H
#define PROJEKT_NEW_HOSTSLIST_H

#include <vector>
#include <map>
#include "ARP_packet.h"

class HostsList {
private:
    map<string, vector<in_addr>> macAddressMap;

public:
    HostsList();

    HostsList(vector<ARP_packet> arpPackets);

    void insert(vector<ARP_packet> arpPackets);

    void exportToXML(string filename);
};


#endif //PROJEKT_NEW_HOSTSLIST_H
