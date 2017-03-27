#include <iostream>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <cstring>
#include "NetworkInterface.h"

NetworkInterface::NetworkInterface(const string &name) : name(name) {
    in_addr mask;

    setPhysicalAddress();

    getAddressesAndMask(ipv4address, ipv6addresses, mask);
    subnet = new Subnet(Utils::getSubnetAddress(ipv4address, mask), mask);
}

NetworkInterface::~NetworkInterface() {
    if (subnet != nullptr)
        delete subnet;
}

void
NetworkInterface::getAddressesAndMask(in_addr &ipv4address, vector<in6_addr> &ipv6addresses, in_addr &mask) {
    int status;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *allInterfaces;
    bool interfaceFound = false;
    bool ipv4addressFound = false;

    ipv6addresses.clear();

    status = pcap_findalldevs(&allInterfaces, errorBuffer);
    if (status == -1)
        throw runtime_error(errorBuffer);

    for (pcap_if_t *interface = allInterfaces; interface != NULL; interface = interface->next) {
        if (interface->name == name) {
            for (pcap_addr *pAddress = interface->addresses; pAddress != NULL; pAddress = pAddress->next) {
                /* IPv4 */
                if (pAddress->addr->sa_family == AF_INET) {
                    ipv4address = ((sockaddr_in *) (pAddress->addr))->sin_addr;
                    mask = ((sockaddr_in *) (pAddress->netmask))->sin_addr;
                    ipv4addressFound = true;
                }

                /* IPv6 */
                if (pAddress->addr->sa_family == AF_INET6) {
                    ipv6addresses.push_back(((sockaddr_in6 *) (pAddress->addr))->sin6_addr);
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

const in_addr &NetworkInterface::getIpv4address() const {
    return ipv4address;
}

const vector<in6_addr> &NetworkInterface::getIpv6addresses() const {
    return ipv6addresses;
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
    cout << "Name:\t\t\t" << name << endl;
    cout << "IPv4 address:\t\t" << inet_ntoa(ipv4address) << endl;
    for (auto &ipv6address : ipv6addresses) {
        array<char, INET6_ADDRSTRLEN> result;
        string ipv6addressString = inet_ntop(AF_INET6, &ipv6address, result.data(), INET6_ADDRSTRLEN);
        if (!ipv6addressString.empty()) {
            cout << "IPv6 address:\t\t" << ipv6addressString << endl;
        }

    }
    cout << "Physical address:\t";
    cout << Utils::formatMacAddress(physicalAddress, six_groups_of_two_hexa_digits_sep_colon);
    cout << endl << endl;
}
