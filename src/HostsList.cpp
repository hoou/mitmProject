#include <iostream>
#include <netinet/in.h>
#include <fstream>
#include <libxml/xmlreader.h>
#include "HostsList.h"

HostsList::HostsList() {}

HostsList::HostsList(vector<ARP_packet *> &arpPackets, vector<ICMPv6_packet *> &icmpv6Packets) {
    insert(arpPackets, icmpv6Packets);
}

HostsList::HostsList(string filename) {
    importFromXML(filename);
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

/* http://www.xmlsoft.org/examples/reader1.c */
void HostsList::importFromXML(string filename) {
    xmlTextReaderPtr reader;
    int ret = 0;
    const xmlChar *name, *value, *attr;
    string nodeName;
    string lastNodeName;
    mac_addr lastMacAddress;

    reader = xmlReaderForFile(filename.c_str(), NULL, 0);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            name = xmlTextReaderConstName(reader);
            if (name == NULL)
                name = BAD_CAST "--";
            nodeName = string((char *) name);

            if (nodeName == "host") {
                attr = xmlTextReaderGetAttribute(reader, BAD_CAST "mac");
                if (attr == NULL)
                    throw runtime_error("Host node is missing mac attribute");

                lastMacAddress = Utils::parseMacAddress((char *) attr);
                Host newHost{lastMacAddress};

                attr = xmlTextReaderGetAttribute(reader, BAD_CAST "group");
                if (attr != NULL) {
                    newHost.setGroup((char *) attr);
                }

                hosts.insert(newHost);
            } else if (lastNodeName == "ipv4" && xmlTextReaderNodeType(reader) == 3) {
                value = xmlTextReaderValue(reader);
                if (value == NULL)
                    throw runtime_error("IPv4 node is missing value");

                set<Host>::iterator it = hosts.find(Host(lastMacAddress));
                Host modifiedHost = (*it);
                modifiedHost.addIpv4Address(Utils::stringToIpv4((char *) value));
                hosts.erase(it);
                hosts.insert(modifiedHost);
            } else if (lastNodeName == "ipv6" && xmlTextReaderNodeType(reader) == 3) {
                value = xmlTextReaderValue(reader);
                if (value == NULL)
                    throw runtime_error("IPv6 node is missing value");

                set<Host>::iterator it = hosts.find(Host(lastMacAddress));
                Host modifiedHost = (*it);
                modifiedHost.addIpv6Address(Utils::stringToIpv6((char *) value));
                hosts.erase(it);
                hosts.insert(modifiedHost);
            }

            lastNodeName = nodeName;
            ret = xmlTextReaderRead(reader);
        }
        xmlFreeTextReader(reader);

    }
    xmlCleanupParser();

    if (reader == NULL) {
        throw runtime_error("Unable to open \'" + filename + "\'");
    }

    if (ret != 0) {
        throw runtime_error("Failed to parse \'" + filename + "\'");
    }
}

void HostsList::remove(mac_addr address) {
    hosts.erase(Host(address));
}

set<Host>::iterator HostsList::find(mac_addr address) {
    return hosts.find(Host(address));
}

const set<Host> &HostsList::getHosts() const {
    return hosts;
}

set<Group> HostsList::getGroups() {
    set<Group> groups;

    for (auto &host : hosts) {
        string groupName = host.getGroupName();
        if (!groupName.empty()) {
            set<Group>::iterator it;
            it = groups.find(Group(groupName, vector<Host>()));
            if (it == groups.end()) {
                groups.insert({groupName, {host}});
            } else {
                Group modifiedGroup = *it;
                modifiedGroup.addHost(host);
                groups.erase(it);
                groups.insert(modifiedGroup);
            }
        }
    }

    return groups;
}

bool HostsList::hasEveryGroupExactlyTwoHosts(set<Group> groups) {
    bool res = true;

    for (auto &group : groups) {
        if (group.getHosts().size() != 2) {
            res = false;
            break;
        }
    }

    return res;
}

bool operator<(const Host a, const Host b) {
    return Utils::formatMacAddress(a.getMacAddress(), three_groups_of_four_hexa_digits_sep_dot) <
           Utils::formatMacAddress(b.getMacAddress(), three_groups_of_four_hexa_digits_sep_dot);
}

bool operator<(const Group a, const Group b) {
    return a.getName() < b.getName();
}
