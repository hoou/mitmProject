#ifndef PROJEKT_NEW_UTILS_H
#define PROJEKT_NEW_UTILS_H

#include <pcap.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <string>

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

    static in_addr constructIPv4addressFromString(string address);

    static string convertIPv4addressToString(const u_int8_t *address);

    static string formatMacAddress(const u_int8_t *address, MacAddressFormat format);
};


#endif //PROJEKT_NEW_UTILS_H
