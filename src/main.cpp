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
        ARP_packetManager::init(&networkInterface);
        
        alarm(10);
        signal(SIGALRM, alarmHandler);

        ARP_packetManager::listen();

        vector<in_addr> allAvailableHostsAddresses = networkInterface.getSubnet()->getAllAvailableHostsAddresses();
        for (vector<in_addr>::iterator availableHostAddressIt = allAvailableHostsAddresses.begin();
             availableHostAddressIt < allAvailableHostsAddresses.end(); availableHostAddressIt++) {
            ARP_packet arpPacket = ARP_packet::request(
                    networkInterface.getPhysicalAddress(), // Sender hardware address
                    networkInterface.getAddress(), // Sender protocol address
                    *availableHostAddressIt // Target protocol address
            );

            ARP_packetManager::sendRequest(arpPacket);
        }

        ARP_packetManager::wait();

        HostsList hostsList(ARP_packetManager::getCaughtARP_packets());
        hostsList.exportToXML(arguments.getFile());

        ARP_packetManager::clean();

    } catch (exception &e) {
        cerr << e.what() << endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void alarmHandler(int sig) {
    ARP_packetManager::stopListen();
}