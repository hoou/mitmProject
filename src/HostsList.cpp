#include <iostream>
#include <fstream>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "HostsList.h"
#include "Utils.h"

HostsList::HostsList() {}

HostsList::HostsList(vector<ARP_packet> arpPackets) {
    insert(arpPackets);
}

void HostsList::insert(vector<ARP_packet> arpPackets) {
    for (auto &arpPacket : arpPackets) {
        map<string, vector<in_addr>>::iterator it;

        const string &senderMacAddress = Utils::formatMacAddress(
                arpPacket.getSenderHardwareAddr(),
                three_groups_of_four_hexa_digits_sep_dot
        );
        if (senderMacAddress != "0000.0000.0000") {
            it = macAddressMap.find(senderMacAddress);

            if (it == macAddressMap.end()) {
                in_addr address;
                inet_aton(Utils::convertIPv4addressToString(arpPacket.getSenderProtocolAddr()).c_str(), &address);
                vector<in_addr> addresses{address};
                macAddressMap.insert(pair<string, vector<in_addr>>(senderMacAddress, addresses));
            }
        }

        const string &targetMacAddress = Utils::formatMacAddress(
                arpPacket.getTargetHardwareAddr(),
                three_groups_of_four_hexa_digits_sep_dot
        );
        if (targetMacAddress != "0000.0000.0000") {
            it = macAddressMap.find(targetMacAddress);

            if (it == macAddressMap.end()) {
                in_addr address;
                inet_aton(Utils::convertIPv4addressToString(arpPacket.getTargetProtocolAddr()).c_str(), &address);
                vector<in_addr> addresses{address};
                macAddressMap.insert(pair<string, vector<in_addr>>(targetMacAddress, addresses));
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
        xmlNewProp(pHostNode, BAD_CAST "mac", BAD_CAST host.first.c_str());
        for (auto &address : host.second) {
            xmlNewChild(pHostNode, NULL, BAD_CAST "ipv4", BAD_CAST inet_ntoa(address));
        }
    }

    status = xmlSaveFormatFileEnc(filename.c_str(), pDocument, "UTF-8", 1);
    if (status == -1)
        throw runtime_error("Cannot create output XML file");
}
