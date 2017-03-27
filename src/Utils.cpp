#include <bitset>
#include <cmath>
#include <sstream>
#include <cstring>
#include "Utils.h"

unsigned long long Utils::calculateNumberOfAvailableHosts(in_addr subnetMask) {
    bitset<32> subnetBitmask(subnetMask.s_addr);
    return (unsigned long long) (pow(2.0, 32 - subnetBitmask.count()) - 2);
}

in_addr Utils::getSubnetAddress(in_addr hostAddress, in_addr subnetMask) {
    in_addr subnetAddress;
    subnetAddress.s_addr = hostAddress.s_addr & subnetMask.s_addr;
    return subnetAddress;
}

mac_addr Utils::constructMacAddressFromRawData(const uint8_t *data) {
    mac_addr address;
    memcpy(address.data(), data, sizeof(uint8_t) * ETH_ALEN);
    return address;
}

mac_addr Utils::constructEthernetBroadcastAddress() {
    return mac_addr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
}

mac_addr Utils::constructEthernetAllNodesMulticastAddress() {
    return mac_addr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01};
}

in_addr Utils::constructIpv4addressFromRawData(const uint8_t *data) {
    stringstream ss;
    in_addr constructedAddress;

    ss << (int) data[0] << "." << (int) data[1] << "." << (int) data[2] << "." << (int) data[3];
    inet_aton(ss.str().c_str(), &constructedAddress);

    return constructedAddress;
}

in6_addr Utils::constructIpv6AllNodesMulticastAddress() {
    string address = "ff02::1";
    in6_addr constructedAddress;

    inet_pton(AF_INET6, address.c_str(), &constructedAddress);

    return constructedAddress;
}

string Utils::ipv6ToString(in6_addr address) {
    array<char, INET6_ADDRSTRLEN> result;
    string ipv6addressString = inet_ntop(AF_INET6, &address, result.data(), INET6_ADDRSTRLEN);
    if (!ipv6addressString.empty()) {
        return ipv6addressString;
    } else {
        return string();
    }
}

string Utils::formatMacAddress(mac_addr address, MacAddressFormat format) {
    bool hasSixGroups;
    string delimiter;
    stringstream ss;
    char buffer[18];

    hasSixGroups = true;

    switch (format) {
        case six_groups_of_two_hexa_digits_sep_hyphen:
            delimiter = "-";
            break;
        case six_groups_of_two_hexa_digits_sep_colon:
            delimiter = ":";
            break;
        case three_groups_of_four_hexa_digits_sep_dot:
            hasSixGroups = false;
            delimiter = ".";
            break;
    }

    ss << "%02x" << (hasSixGroups ? delimiter : "")
       << "%02x" << delimiter
       << "%02x" << (hasSixGroups ? delimiter : "")
       << "%02x" << delimiter
       << "%02x" << (hasSixGroups ? delimiter : "")
       << "%02x";
    sprintf(buffer, ss.str().c_str(),
            (unsigned char) address[0],
            (unsigned char) address[1],
            (unsigned char) address[2],
            (unsigned char) address[3],
            (unsigned char) address[4],
            (unsigned char) address[5]);
    return string(buffer);
}

bool Utils::isZeroMacAddress(mac_addr address) {
    return address.at(0) == 0 &&
           address.at(1) == 0 &&
           address.at(2) == 0 &&
           address.at(3) == 0 &&
           address.at(4) == 0 &&
           address.at(5) == 0;
}
