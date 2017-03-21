#include <bitset>
#include <cmath>
#include <sstream>
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

string Utils::convertIPv4addressToString(const u_int8_t *address) {
    stringstream ss;
    ss << (int) address[0] << "." << (int) address[1] << "." << (int) address[2] << "." << (int) address[3];
    return ss.str();
}

string Utils::formatMacAddress(const u_int8_t *address, MacAddressFormat format) {
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

in_addr Utils::constructIPv4addressFromString(string address) {
    in_addr constructedAddress;
    inet_aton(address.c_str(), &constructedAddress);
    return constructedAddress;
}
