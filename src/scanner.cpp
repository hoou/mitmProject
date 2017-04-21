#include <iostream>
#include <unistd.h>
#include <signal.h>
#include "NetworkInterface.h"
#include "ScannerArguments.h"
#include "SetOfHosts.h"
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

        for (auto &ipv4address : networkInterface.getHost()->getIpv4addresses()) {
            vector<in_addr> allPossibleHostAddresses = ipv4address.second.getAllPossibleHostAddresses();
            for (
                    vector<in_addr>::iterator possibleHostAddressIt = allPossibleHostAddresses.begin();
                    possibleHostAddressIt < allPossibleHostAddresses.end();
                    possibleHostAddressIt++
                    ) {
                ARP_packet *arpPacket = ARP_packet::createRequest(
                        networkInterface.getHost()->getMacAddress(),
                        ipv4address.first,
                        *possibleHostAddressIt
                );

                arpPacketManager.send(arpPacket);

                delete (arpPacket);

                usleep(1);
            }
        }

        icmpv6PacketManager.listen();

        for (auto &myIPv6address : networkInterface.getHost()->getIpv6addresses()) {
            ICMPv6_packet *icmpv6Packet = ICMPv6_packet::createEchoRequest(
                    networkInterface.getHost()->getMacAddress(),
                    Utils::constructEthernetAllNodesMulticastAddress(),
                    myIPv6address,
                    Utils::constructIpv6AllNodesMulticastAddress()
            );
            ICMPv6_packet *malformedIcmpv6Packet = ICMPv6_packet::createMalformedEchoRequest(
                    networkInterface.getHost()->getMacAddress(),
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

        for (auto &myIPv6address : networkInterface.getHost()->getIpv6addresses()) {
            ICMPv6_packet *icmpv6Packet = ICMPv6_packet::createMulticastListenerQuery(
                    networkInterface.getHost()->getMacAddress(),
                    myIPv6address,
                    Utils::constructEthernetAllNodesMulticastAddress(),
                    Utils::constructIpv6AllNodesMulticastAddress(),
                    Utils::stringToIpv6("::")
            );

            icmpv6PacketManager.send(icmpv6Packet);
            usleep(1);
            delete icmpv6Packet;
        }

        alarm(20);
        signal(SIGALRM, signalHandler);

        arpPacketManager.wait();
        icmpv6PacketManager.wait();

        SetOfHosts hostsList(
                (vector<ARP_packet *> &) arpPacketManager.getCaughtPackets(),
                (vector<ICMPv6_packet *> &) icmpv6PacketManager.getCaughtPackets()
        );

        /* Remove my mac address from hosts list */
        hostsList.remove(networkInterface.getHost()->getMacAddress());

        hostsList.exportToXML(arguments.getFile());

    }
    catch (InvalidArgumentsException &e) {
        cerr << e.what() << endl;
        ScannerArguments::printUsage();
        return EXIT_FAILURE;
    }
    catch (exception &e) {
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