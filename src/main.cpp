#include <iostream>
#include <unistd.h>
#include <signal.h>
#include "Arguments.h"
#include "ARP_packetManager.h"
#include "HostsList.h"
#include "ICMPv6_packetManager.h"
#include "ICMPv6_packet.h"

void alarmHandler(int sig);

int main(int argc, char **argv) {
    try {
        Arguments arguments(argc, argv);
        NetworkInterface networkInterface(arguments.getInterface());
        ARP_packetManager *arpPacketManager;
        ICMPv6_packetManager *icmpv6PacketManager;

        networkInterface.print();

        arpPacketManager = ARP_packetManager::getInstance();
        icmpv6PacketManager = ICMPv6_packetManager::getInstance();

        arpPacketManager->init(&networkInterface);

        arpPacketManager->listen();

        vector<in_addr> allAvailableHostsAddresses = networkInterface.getSubnet()->getAllAvailableHostsAddresses();
        for (vector<in_addr>::iterator availableHostAddressIt = allAvailableHostsAddresses.begin();
             availableHostAddressIt < allAvailableHostsAddresses.end(); availableHostAddressIt++) {
            ARP_packet *arpPacket = ARP_packet::createRequest(
                    networkInterface.getPhysicalAddress(), // Sender hardware address
                    networkInterface.getIpv4address(), // Sender protocol address
                    *availableHostAddressIt // Target protocol address
            );

            arpPacketManager->send(arpPacket);

            delete (arpPacket);

            usleep(1);
        }

        icmpv6PacketManager->init(&networkInterface);

        icmpv6PacketManager->listen();

        ICMPv6_packet *icmpv6Packet = ICMPv6_packet::createEchoRequest(
                networkInterface.getPhysicalAddress(),
                Utils::constructEthernetAllNodesMulticastAddress(),
                networkInterface.getIpv6addresses().at(0),
                Utils::constructIpv6AllNodesMulticastAddress()
        );

        icmpv6PacketManager->send(icmpv6Packet);

        delete icmpv6Packet;

        alarm(5);
        signal(SIGALRM, alarmHandler);

        arpPacketManager->wait();
        icmpv6PacketManager->wait();

        HostsList hostsList(arpPacketManager->getCaughtARP_packets());
        hostsList.exportToXML(arguments.getFile());

        arpPacketManager->clean();
        icmpv6PacketManager->clean();

    } catch (exception &e) {
        cerr << e.what() << endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void alarmHandler(int sig) {
    ARP_packetManager::getInstance()->stopListen();
    ICMPv6_packetManager::getInstance()->stopListen();
}