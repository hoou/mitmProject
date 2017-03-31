#include <iostream>
#include <csignal>
#include "ScannerArguments.h"
#include "NetworkInterface.h"
#include "Packet.h"
#include "InterceptPacketManager.h"
#include "HostsList.h"

void interruptHandler(int sig);

int main(int argc, char *argv[]) {
    try {
        ScannerArguments arguments(argc, argv);


        HostsList hostsList;
        hostsList.importFromXML(arguments.getFile());

        for (auto &host : hostsList.getHosts()) {
            cout << host << endl << endl;
        }

        return EXIT_SUCCESS;

        NetworkInterface networkInterface(arguments.getInterface());
        InterceptPacketManager packetManager1(networkInterface, "src");

        signal(SIGINT, interruptHandler);
        signal(SIGTERM, interruptHandler);

        packetManager1.listen();
        packetManager1.wait();

        cout << "packet count:" << packetManager1.getCaughtPackets().size() << endl;

    } catch (exception &e) {
        cerr << e.what() << endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void interruptHandler(int sig) {
    vector<PacketManager<Packet> *> instances = PacketManager<Packet>::getInstances();
    for (auto &instance : instances) {
        instance->stopListen();
    }
}