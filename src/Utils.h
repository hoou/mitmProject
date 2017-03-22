#ifndef PROJEKT_NEW_UTILS_H
#define PROJEKT_NEW_UTILS_H

#include <pcap.h>
#include <arpa/inet.h>
#include <string>
#include <array>
#include <linux/if_ether.h>

using namespace std;

enum MacAddressFormat {
    six_groups_of_two_hexa_digits_sep_hyphen, // e.g. 01-23-45-67-89-ab
    six_groups_of_two_hexa_digits_sep_colon, // e.g. 01:23:45:67:89:ab
    three_groups_of_four_hexa_digits_sep_dot // e.g. 0123.4567.89ab
};

class Utils {
public:
    static unsigned long long calculateNumberOfAvailableHosts(in_addr subnetMask);

    static in_addr getSubnetAddress(in_addr hostAddress, in_addr subnetMask);

    static array<u_int8_t, (size_t) ETH_ALEN> constructMacAddressFromRawData(const u_int8_t *data);

    static in_addr constructIpv4addressFromRawData(const u_int8_t *data);

    static string formatMacAddress(array<u_int8_t, (size_t) ETH_ALEN> address, MacAddressFormat format);

    static bool isZeroMacAddress(array<u_int8_t, (size_t) ETH_ALEN> address);
};


#endif //PROJEKT_NEW_UTILS_H
