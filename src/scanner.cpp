#include <iostream>
#include <unistd.h>
#include <signal.h>
#include "NetworkInterface.h"
#include "ScannerArguments.h"
#include "HostsList.h"
#include "PacketManager.h"

void signalHandler(int sig);

int main(int argc, char **argv) {
    try {
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);

        ScannerArguments arguments(argc, argv);
        NetworkInterface networkInterface(arguments.getInterface());
        PacketManager<ARP_packet> arpPacketManager(networkInterface, "arp");
        PacketManager<ICMPv6_packet> icmpv6PacketManager(networkInterface, "icmp6");

        arpPacketManager.listen();

        vector<in_addr> allPossibleHostAddresses = networkInterface.getSubnet()->getAllPossibleHostAddresses();
        for (
                vector<in_addr>::iterator possibleHostAddressIt = allPossibleHostAddresses.begin();
                possibleHostAddressIt < allPossibleHostAddresses.end();
                possibleHostAddressIt++
                ) {
            ARP_packet *arpPacket = ARP_packet::createRequest(
                    networkInterface.getPhysicalAddress(),
                    networkInterface.getIpv4address(),
                    *possibleHostAddressIt
            );

            arpPacketManager.send(arpPacket);

            delete (arpPacket);

            usleep(1);
        }

        icmpv6PacketManager.listen();

        for (auto &myIPv6address : networkInterface.getIpv6addresses()) {
            ICMPv6_packet *icmpv6Packet = ICMPv6_packet::createEchoRequest(
                    networkInterface.getPhysicalAddress(),
                    Utils::constructEthernetAllNodesMulticastAddress(),
                    myIPv6address,
                    Utils::constructIpv6AllNodesMulticastAddress()
            );
            ICMPv6_packet *malformedIcmpv6Packet = ICMPv6_packet::createMalformedEchoRequest(
                    networkInterface.getPhysicalAddress(),
                    Utils::constructEthernetAllNodesMulticastAddress(),
                    myIPv6address,
                    Utils::constructIpv6AllNodesMulticastAddress()
            );

            icmpv6PacketManager.send(icmpv6Packet);
            usleep(1);
            icmpv6PacketManager.send(malformedIcmpv6Packet);
            usleep(1);

            delete icmpv6Packet;
            delete malformedIcmpv6Packet;
        }

        alarm(20);
        signal(SIGALRM, signalHandler);

        arpPacketManager.wait();
        icmpv6PacketManager.wait();

        HostsList hostsList(
                (vector<ARP_packet *> &) arpPacketManager.getCaughtPackets(),
                (vector<ICMPv6_packet *> &) icmpv6PacketManager.getCaughtPackets()
        );

        /* Remove my mac address from hosts list */
        hostsList.remove(networkInterface.getPhysicalAddress());

        hostsList.exportToXML(arguments.getFile());

    } catch (exception &e) {
        cerr << e.what() << endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void signalHandler(int sig) {
    vector<PacketManager<ARP_packet> *> arpInstances = PacketManager<ARP_packet>::getInstances();
    for (auto &instance : arpInstances) {
        instance->stopListen();
    }

    vector<PacketManager<ICMPv6_packet> *> icmpInstances = PacketManager<ICMPv6_packet>::getInstances();
    for (auto &instance : icmpInstances) {
        instance->stopListen();
    }
}