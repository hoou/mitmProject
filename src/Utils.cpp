#include <bitset>
#include <cmath>
#include <sstream>
#include <cstring>
#include <iostream>
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
    return Utils::stringToIpv6("ff02::1");
}

string Utils::ipv6ToString(in6_addr address) {
    array<char, INET6_ADDRSTRLEN> result;
    string ipv6addressString = inet_ntop(AF_INET6, &address, result.data(), INET6_ADDRSTRLEN);
    if (!ipv6addressString.empty()) {
        return ipv6addressString;
    } else {
        throw InvalidFormatException();
    }
}

string Utils::ipv4ToString(in_addr address) {
    array<char, INET_ADDRSTRLEN> result;
    string ipv4addressString = inet_ntop(AF_INET, &address, result.data(), INET_ADDRSTRLEN);
    if (!ipv4addressString.empty()) {
        return ipv4addressString;
    } else {
        throw InvalidFormatException();
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

mac_addr Utils::parseMacAddress(string address) {
    char values[ETH_ALEN];
    uint8_t bytes[ETH_ALEN];
    int i;

    if (6 == (sscanf(address.c_str(), "%02hhx-%02hhx-%02hhx-%02hhx-%02hhx-%02hhx",
                     &values[0], &values[1], &values[2],
                     &values[3], &values[4], &values[5]))) {

        /* convert to uint8_t */
        for (i = 0; i < ETH_ALEN; ++i)
            bytes[i] = (uint8_t) values[i];
    } else if (6 == (sscanf(address.c_str(), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                            &values[0], &values[1], &values[2],
                            &values[3], &values[4], &values[5]))) {

        /* convert to uint8_t */
        for (i = 0; i < ETH_ALEN; ++i)
            bytes[i] = (uint8_t) values[i];
    } else if (6 == (sscanf(address.c_str(), "%02hhx%02hhx.%02hhx%02hhx.%02hhx%02hhx",
                            &values[0], &values[1], &values[2],
                            &values[3], &values[4], &values[5]))) {

        /* convert to uint8_t */
        for (i = 0; i < ETH_ALEN; ++i) {
            bytes[i] = (uint8_t) values[i];
        }
    } else {
        throw InvalidFormatException("mac address");
    }

    return constructMacAddressFromRawData(bytes);
}

bool Utils::isZeroMacAddress(mac_addr address) {
    return address.at(0) == 0 &&
           address.at(1) == 0 &&
           address.at(2) == 0 &&
           address.at(3) == 0 &&
           address.at(4) == 0 &&
           address.at(5) == 0;
}

mac_addr Utils::constructZeroMacAddress() {
    return mac_addr{0, 0, 0, 0, 0, 0};
}

in_addr Utils::stringToIpv4(string address) {
    in_addr res;
    int status;

    status = inet_pton(AF_INET, address.c_str(), &res);
    if (status == 1) {
        return res;
    } else {
        throw InvalidFormatException(address);
    }
}

in6_addr Utils::stringToIpv6(string address) {
    in6_addr res;
    int status;

    status = inet_pton(AF_INET6, address.c_str(), &res);
    if (status == 1) {
        return res;
    } else {
        throw InvalidFormatException(address);
    }
}

string Utils::hexStr(unsigned char *data, int len) {
    string s((unsigned long) (len * 2), ' ');
    for (int i = 0; i < len; ++i) {
        s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
        s[2 * i + 1] = hexmap[data[i] & 0x0F];
    }
    return s;
}

InvalidFormatException::InvalidFormatException() : runtime_error("Invalid format") {}

InvalidFormatException::InvalidFormatException(const string &__arg) : runtime_error("Invalid format: " + __arg) {}
