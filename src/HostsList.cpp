#include <iostream>
#include <libxml/parser.h>

#include "HostsList.h"
#include "Utils.h"

HostsList::HostsList() {}

HostsList::HostsList(vector<ARP_packet> arpPackets) {
    insert(arpPackets);
}

void HostsList::insert(vector<ARP_packet> arpPackets) {
    for (auto &arpPacket : arpPackets) {
        map<array<u_int8_t, ETH_ALEN>, vector<in_addr>>::iterator it;

        if (!Utils::isZeroMacAddress(arpPacket.getSenderHardwareAddr())) {
            it = macAddressMap.find(arpPacket.getSenderHardwareAddr());

            if (it == macAddressMap.end()) {
                vector<in_addr> addresses{arpPacket.getSenderProtocolAddr()};
                macAddressMap.insert(
                        pair<array<u_int8_t, ETH_ALEN>, vector<in_addr>>(arpPacket.getSenderHardwareAddr(), addresses)
                );
            }
        }

        if (!Utils::isZeroMacAddress(arpPacket.getTargetHardwareAddr())) {
            it = macAddressMap.find(arpPacket.getTargetHardwareAddr());

            if (it == macAddressMap.end()) {
                vector<in_addr> addresses{arpPacket.getTargetProtocolAddr()};
                macAddressMap.insert(
                        pair<array<u_int8_t, ETH_ALEN>, vector<in_addr>>(arpPacket.getTargetHardwareAddr(), addresses)
                );
            }
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
        for (auto &address : host.second) {
            xmlNewChild(pHostNode, NULL, BAD_CAST "ipv4", BAD_CAST inet_ntoa(address));
        }
    }

    status = xmlSaveFormatFileEnc(filename.c_str(), pDocument, "UTF-8", 1);

    xmlFreeDoc(pDocument);
    xmlCleanupParser();

    if (status == -1)
        throw runtime_error("Cannot create output XML file");
}
