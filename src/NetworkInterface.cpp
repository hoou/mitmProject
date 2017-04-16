#include <iostream>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <cstring>
#include "NetworkInterface.h"

NetworkInterface::NetworkInterface(const string &name) : name(name) {
    mac_addr physicalAddress;

    physicalAddress = retrievePhysicalAddress(name);

    host = new Host(physicalAddress);

    retrieveAddressesByName(name, host);
}

NetworkInterface::~NetworkInterface() {
    delete host;
}

void NetworkInterface::retrieveAddressesByName(string name, Host *host) {
    int status;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *allInterfaces;
    bool interfaceFound = false;
    bool ipv4addressFound = false;

    status = pcap_findalldevs(&allInterfaces, errorBuffer);
    if (status == -1)
        throw runtime_error(errorBuffer);

    for (pcap_if_t *interface = allInterfaces; interface != NULL; interface = interface->next) {
        if (interface->name == name) {
            for (pcap_addr *pAddress = interface->addresses; pAddress != NULL; pAddress = pAddress->next) {
                /* IPv4 */
                if (pAddress->addr->sa_family == AF_INET) {
                    host->addIpv4Address(((sockaddr_in *) (pAddress->addr))->sin_addr,
                                         ((sockaddr_in *) (pAddress->netmask))->sin_addr);
                    ipv4addressFound = true;
                }

                /* IPv6 */
                if (pAddress->addr->sa_family == AF_INET6) {
                    host->addIpv6Address(((sockaddr_in6 *) (pAddress->addr))->sin6_addr);
                }
            }
            interfaceFound = true;
            break;
        }
    }

    if (!interfaceFound)
        throw runtime_error("Interface " + name + " not found");

    if (!ipv4addressFound)
        throw runtime_error("No IPv4 address found");

    pcap_freealldevs(allInterfaces);
}

mac_addr NetworkInterface::retrievePhysicalAddress(string name) {
    int status;
    int socketDescriptor;
    struct ifreq interfaceStructure;
    mac_addr physicalAddress;

    /* Create socket */
    socketDescriptor = socket(PF_INET, SOCK_DGRAM, 0);
    if (socketDescriptor < 0)
        throw runtime_error("Cannot create a new socket");

    /* Setup interface name */
    strcpy(interfaceStructure.ifr_name, name.c_str());

    // Get interface physical address (MAC)
    status = ioctl(socketDescriptor, SIOCGIFHWADDR, &interfaceStructure);
    if (status == 0) {
        memcpy(physicalAddress.data(), interfaceStructure.ifr_hwaddr.sa_data, 6);
    }

    close(socketDescriptor);

    if (status != 0)
        throw runtime_error("Cannot retrieve physical address of interface");

    return physicalAddress;
}

Host *NetworkInterface::getHost() const {
    return host;
}

const string &NetworkInterface::getName() const {
    return name;
}
