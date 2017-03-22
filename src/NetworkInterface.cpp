#include <iostream>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <cstring>
#include "NetworkInterface.h"

NetworkInterface::NetworkInterface(const string &name) : name(name) {
    in_addr mask;

    setPhysicalAddress();
    mask = setAddressAndGetMask();
    subnet = new Subnet(Utils::getSubnetAddress(address, mask), mask);
}

NetworkInterface::~NetworkInterface() {
    if (subnet != nullptr)
        delete subnet;
}

in_addr NetworkInterface::setAddressAndGetMask() {
    int status;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *allInterfaces;
    bool interfaceFound = false;
    bool addressFound = false;
    in_addr mask = in_addr();

    status = pcap_findalldevs(&allInterfaces, errorBuffer);
    if (status == -1)
        throw runtime_error(errorBuffer);

    for (pcap_if_t *interface = allInterfaces; interface != NULL; interface = interface->next) {
        if (interface->name == name) {
            for (pcap_addr *pAddress = interface->addresses; pAddress != NULL; pAddress = pAddress->next) {
                if (pAddress->addr->sa_family == AF_INET) {
                    address = ((sockaddr_in *) (pAddress->addr))->sin_addr;
                    mask = ((sockaddr_in *) (pAddress->netmask))->sin_addr;
                    addressFound = true;
                    break;
                }
            }
            interfaceFound = true;
            break;
        }
    }

    if (!interfaceFound)
        throw runtime_error("Interface " + name + " not found");

    if (!addressFound)
        throw runtime_error("No IPv4 address found");

    pcap_freealldevs(allInterfaces);

    return mask;
}

void NetworkInterface::setPhysicalAddress() {
    int status;
    int socketDescriptor;
    struct ifreq interfaceStruct;

    /* Create socket */
    socketDescriptor = socket(PF_INET, SOCK_DGRAM, 0);
    if (socketDescriptor < 0)
        throw runtime_error("Cannot create a new socket");

    /* Setup interface name */
    strcpy(interfaceStruct.ifr_name, name.c_str());

    // Get interface physical address (MAC)
    status = ioctl(socketDescriptor, SIOCGIFHWADDR, &interfaceStruct);
    if (status == 0) {
        memcpy(physicalAddress.data(), interfaceStruct.ifr_hwaddr.sa_data, 6);
    }

    close(socketDescriptor);

    if (status != 0)
        throw runtime_error("Cannot retrieve physical address of interface");
}

const in_addr &NetworkInterface::getAddress() const {
    return address;
}

const mac_addr &NetworkInterface::getPhysicalAddress() const {
    return physicalAddress;
}

const string &NetworkInterface::getName() const {
    return name;
}

Subnet *NetworkInterface::getSubnet() const {
    return subnet;
}

void NetworkInterface::print() {
    cout << "Name:\t\t\t\t" << name << endl;
    cout << "Address:\t\t\t" << inet_ntoa(address) << endl;
    cout << "Physical address:\t";
    cout << Utils::formatMacAddress(physicalAddress, six_groups_of_two_hexa_digits_sep_colon);
    cout << endl << endl;
}
