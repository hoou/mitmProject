#include <iostream>
#include <libxml/parser.h>
#include <netinet/in.h>

#include "HostsList.h"

HostsList::HostsList() {}

HostsList::HostsList(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets) {
    insert(arpPackets, icmpv6Packets);
}

bool operator<(in6_addr a, in6_addr b) {
    char aStr[INET6_ADDRSTRLEN];
    char bStr[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &a, aStr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &b, bStr, INET6_ADDRSTRLEN);

    return string(aStr) != string(bStr);
}

void HostsList::insert(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets) {
    for (auto &arpPacket : arpPackets) {
        map<mac_addr, pair<vector<in_addr>, set<in6_addr>>>::iterator it;

        if (!Utils::isZeroMacAddress(arpPacket->getSenderHardwareAddr())) {
            it = macAddressMap.find(arpPacket->getSenderHardwareAddr());

            if (it == macAddressMap.end()) {
                vector<in_addr> ipv4addresses{arpPacket->getSenderProtocolAddr()};
                set<in6_addr> ipv6addresses;
                pair<vector<in_addr>, set<in6_addr>> addresses{ipv4addresses, ipv6addresses};
                macAddressMap.insert(pair<mac_addr, pair<vector<in_addr>, set<in6_addr>>>(arpPacket->getSenderHardwareAddr(), addresses));
            }
        }

        if (!Utils::isZeroMacAddress(arpPacket->getTargetHardwareAddr())) {
            it = macAddressMap.find(arpPacket->getTargetHardwareAddr());

            if (it == macAddressMap.end()) {
                vector<in_addr> ipv4addresses{arpPacket->getSenderProtocolAddr()};
                set<in6_addr> ipv6addresses;
                pair<vector<in_addr>, set<in6_addr>> addresses{ipv4addresses, ipv6addresses};
                macAddressMap.insert(pair<mac_addr, pair<vector<in_addr>, set<in6_addr>>>(arpPacket->getTargetHardwareAddr(), addresses));
            }
        }
    }

    for(auto &icmpPacket : icmpv6Packets) {
        map<mac_addr, pair<vector<in_addr>, set<in6_addr>>>::iterator it;

        it = macAddressMap.find(icmpPacket->getEthernetSourceAddress());
        if (it != macAddressMap.end()) {
            it->second.second.insert(icmpPacket->getSourceAddress());
        }

        it = macAddressMap.find(icmpPacket->getEthernetDestinationAddress());
        if (it != macAddressMap.end()) {
            it->second.second.insert(icmpPacket->getDestinationAddress());
        }
    }
}

/* http://www.linuxquestions.org/questions/programming-9/creating-an-xml-file-using-libxml-745532/ */
void HostsList::exportToXML(string filename) {
    int status;
    xmlDocPtr pDocument;
    xmlNodePtr pRootNode;

    pDocument = xmlNewDoc(BAD_CAST "1.0");
    pRootNode = xmlNewNode(NULL, BAD_CAST "devices");
    xmlDocSetRootElement(pDocument, pRootNode);

    for (auto &host : macAddressMap) {
        xmlNodePtr pHostNode = xmlNewChild(pRootNode, NULL, BAD_CAST "host", NULL);
        xmlNewProp(
                pHostNode, BAD_CAST "mac",
                BAD_CAST Utils::formatMacAddress(host.first, three_groups_of_four_hexa_digits_sep_dot).c_str()
        );

        /* IPv4 addresses */
        for (auto &address : host.second.first) {
            xmlNewChild(pHostNode, NULL, BAD_CAST "ipv4", BAD_CAST inet_ntoa(address));
        }

        /* IPv6 addresses */
        for (auto &address : host.second.second) {
            char addressString[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &address, addressString, INET6_ADDRSTRLEN);
            xmlNewChild(pHostNode, NULL, BAD_CAST "ipv6", BAD_CAST addressString);
        }
    }

    status = xmlSaveFormatFileEnc(filename.c_str(), pDocument, "UTF-8", 1);

    xmlFreeDoc(pDocument);
    xmlCleanupParser();

    if (status == -1)
        throw runtime_error("Cannot create output XML file");
}

void HostsList::remove(mac_addr address) {
    macAddressMap.erase(address);
}
