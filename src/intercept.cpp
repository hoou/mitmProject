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
        NetworkInterface networkInterface(arguments.getInterface());

        HostsList hostsList;
        hostsList.importFromXML(arguments.getFile());

        set<Group> groupsOfVictims = hostsList.getGroups();
        if (!HostsList::hasEveryGroupExactlyTwoHosts(groupsOfVictims)) {
            throw runtime_error("Every group must have exactly 2 hosts!");
        }

        signal(SIGINT, interruptHandler);
        signal(SIGTERM, interruptHandler);

        set<in6_addr> ipv6addresses;
        for (auto &group : groupsOfVictims) {
            InterceptPacketManager *packetManager1to2 = new InterceptPacketManager(networkInterface,
                                                                                   group.getHosts()[0],
                                                                                   group.getHosts()[1]);
            InterceptPacketManager *packetManager2to1 = new InterceptPacketManager(networkInterface,
                                                                                   group.getHosts()[1],
                                                                                   group.getHosts()[0]);
            packetManager1to2->listen();
            packetManager2to1->listen();
        }

        for (auto &instance : InterceptPacketManager::getInstances()) {
            instance->wait();
        }

        vector<PacketManager<Packet> *> instances = PacketManager<Packet>::getInstances();
        for (auto &instance : instances) {
            delete instance;
        }

        return EXIT_SUCCESS;

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