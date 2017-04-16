#include <iostream>
#include "Subnet.h"
#include "Utils.h"

Subnet::Subnet(const in_addr &address, const in_addr &mask) : address(address), mask(mask) {
    numberOfAvailableHosts = Utils::calculateNumberOfAvailableHosts(this->mask);

    broadcastAddress.s_addr = ntohl((uint32_t) (htonl(this->address.s_addr) + numberOfAvailableHosts + 1));

    firstAvailableHostAddress.s_addr = ntohl(htonl(this->address.s_addr) + 1);
    lastAvailableHostAddress.s_addr = ntohl(htonl(broadcastAddress.s_addr) - 1);
}

vector<in_addr> Subnet::getAllPossibleHostAddresses() const {
    vector<in_addr> addresses;
    for (unsigned int i = 0; i < getNumberOfAvailableHosts(); i++) {
        in_addr address;
        address.s_addr = ntohl(htonl(getFirstAvailableHostAddress().s_addr) + i);
        addresses.push_back(address);
    }
    return addresses;
}


void Subnet::print() {
    cout << "Address:\t\t\t\t\t\t" << inet_ntoa(address) << endl;
    cout << "Mask:\t\t\t\t\t\t\t" << inet_ntoa(mask) << endl;
    cout << "Number of available hosts:\t\t" << numberOfAvailableHosts << endl;
    cout << "First available host address:\t" << inet_ntoa(firstAvailableHostAddress) << endl;
    cout << "Last available host address:\t" << inet_ntoa(lastAvailableHostAddress) << endl;
    cout << "Broadcast address:\t\t\t\t" << inet_ntoa(broadcastAddress) << endl;
}

const in_addr &Subnet::getAddress() const {
    return address;
}

const in_addr &Subnet::getMask() const {
    return mask;
}

const in_addr &Subnet::getFirstAvailableHostAddress() const {
    return firstAvailableHostAddress;
}

const in_addr &Subnet::getLastAvailableHostAddress() const {
    return lastAvailableHostAddress;
}

const in_addr &Subnet::getBroadcastAddress() const {
    return broadcastAddress;
}

unsigned long long int Subnet::getNumberOfAvailableHosts() const {
    return numberOfAvailableHosts;
}
