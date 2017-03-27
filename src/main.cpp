#include <iostream>
#include <unistd.h>
#include <signal.h>
#include "Arguments.h"
#include "ARP_packetManager.h"
#include "HostsList.h"

void alarmHandler(int sig);

int main(int argc, char **argv) {
    try {
        Arguments arguments(argc, argv);
        NetworkInterface networkInterface(arguments.getInterface());
        ARP_packetManager *arp_packetManager;

        arp_packetManager = ARP_packetManager::getInstance();

        arp_packetManager->init(&networkInterface);

        arp_packetManager->listen();

        vector<in_addr> allAvailableHostsAddresses = networkInterface.getSubnet()->getAllAvailableHostsAddresses();
        for (vector<in_addr>::iterator availableHostAddressIt = allAvailableHostsAddresses.begin();
             availableHostAddressIt < allAvailableHostsAddresses.end(); availableHostAddressIt++) {
            ARP_packet *arpPacket = ARP_packet::createRequest(
                    networkInterface.getPhysicalAddress(), // Sender hardware address
                    networkInterface.getAddress(), // Sender protocol address
                    *availableHostAddressIt // Target protocol address
            );

            arp_packetManager->send(arpPacket);

            delete (arpPacket);

            usleep(1);
        }

        alarm(5);
        signal(SIGALRM, alarmHandler);

        arp_packetManager->wait();

        HostsList hostsList(arp_packetManager->getCaughtARP_packets());
        hostsList.exportToXML(arguments.getFile());

        arp_packetManager->clean();

    } catch (exception &e) {
        cerr << e.what() << endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void alarmHandler(int sig) {
    ARP_packetManager::getInstance()->stopListen();
}