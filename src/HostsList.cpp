#include <iostream>
#include <libxml/parser.h>
#include <netinet/in.h>

#include "HostsList.h"

HostsList::HostsList() {}

HostsList::HostsList(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets) {
    insert(arpPackets, icmpv6Packets);
}

void HostsList::insert(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets) {
    set<Host>::iterator it;

    for (auto &arpPacket : arpPackets) {
        if (!Utils::isZeroMacAddress(arpPacket->getSenderHardwareAddr())) {
            it = find(arpPacket->getSenderHardwareAddr());

            if (it == hosts.end()) {
                Host newHost(arpPacket->getSenderHardwareAddr());
                newHost.addIpv4Address(arpPacket->getSenderProtocolAddr());
                hosts.insert(newHost);
            }
        }

        if (!Utils::isZeroMacAddress(arpPacket->getTargetHardwareAddr())) {
            it = find(arpPacket->getTargetHardwareAddr());

            if (it == hosts.end()) {
                Host newHost(arpPacket->getTargetHardwareAddr());
                newHost.addIpv4Address(arpPacket->getTargetProtocolAddr());
                hosts.insert(newHost);
            }
        }
    }

    for (auto &icmpPacket : icmpv6Packets) {
        it = hosts.find(Host(icmpPacket->getEthernetSourceAddress()));
        if (it != hosts.end()) {
            Host modifiedHost = *it;
            modifiedHost.addIpv6Address(icmpPacket->getSourceAddress());
            hosts.erase(it);
            hosts.insert(modifiedHost);
        }

        it = hosts.find(Host(icmpPacket->getEthernetDestinationAddress()));
        if (it != hosts.end()) {
            Host modifiedHost = *it;
            modifiedHost.addIpv6Address(icmpPacket->getDestinationAddress());
            hosts.erase(it);
            hosts.insert(modifiedHost);
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

    for (auto &host : hosts) {
        xmlNodePtr pHostNode = xmlNewChild(pRootNode, NULL, BAD_CAST "host", NULL);
        xmlNewProp(
                pHostNode, BAD_CAST "mac",
                BAD_CAST Utils::formatMacAddress(host.getMacAddress(),
                                                 three_groups_of_four_hexa_digits_sep_dot).c_str()
        );

        /* IPv4 addresses */
        for (auto &address : host.getIpv4addresses()) {
            xmlNewChild(pHostNode, NULL, BAD_CAST "ipv4", BAD_CAST Utils::ipv4ToString(address).c_str());
        }

        /* IPv6 addresses */
        for (auto &address : host.getIpv6addresses()) {
            xmlNewChild(pHostNode, NULL, BAD_CAST "ipv6", BAD_CAST Utils::ipv6ToString(address).c_str());
        }
    }

    status = xmlSaveFormatFileEnc(filename.c_str(), pDocument, "UTF-8", 1);

    xmlFreeDoc(pDocument);
    xmlCleanupParser();

    if (status == -1)
        throw runtime_error("Cannot create output XML file");
}

void HostsList::remove(mac_addr address) {
    hosts.erase(Host(address));
}

set<Host>::iterator HostsList::find(mac_addr address) {
    return hosts.find(Host(address));
}

bool operator<(const Host a, const Host b) {
    return Utils::formatMacAddress(a.getMacAddress(), three_groups_of_four_hexa_digits_sep_dot) <
           Utils::formatMacAddress(b.getMacAddress(), three_groups_of_four_hexa_digits_sep_dot);
}
