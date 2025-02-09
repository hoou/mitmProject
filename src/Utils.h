#ifndef PDS_MITM_UTILS_H
#define PDS_MITM_UTILS_H

#include <pcap.h>
#include <arpa/inet.h>
#include <string>
#include <array>
#include <linux/if_ether.h>

using namespace std;

constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

enum MacAddressFormat {
    six_groups_of_two_hexa_digits_sep_hyphen, // e.g. 01-23-45-67-89-ab
    six_groups_of_two_hexa_digits_sep_colon, // e.g. 01:23:45:67:89:ab
    three_groups_of_four_hexa_digits_sep_dot // e.g. 0123.4567.89ab
};

typedef array<uint8_t, (size_t) ETH_ALEN> mac_addr;

class InvalidFormatException : public runtime_error {
public:
    InvalidFormatException();

    InvalidFormatException(const string &__arg);
};

/**
 * Utility class mostly for working with all kinds of addresses.
 */
class Utils {
public:
    static unsigned long long calculateNumberOfAvailableHosts(in_addr subnetMask);

    static in_addr getSubnetAddress(in_addr hostAddress, in_addr subnetMask);

    static mac_addr constructZeroMacAddress();

    static mac_addr constructMacAddressFromRawData(const uint8_t *data);

    static mac_addr constructEthernetBroadcastAddress();

    static mac_addr constructEthernetAllNodesMulticastAddress();

    static in_addr constructIpv4addressFromRawData(const uint8_t *data);

    static in6_addr constructIpv6AllNodesMulticastAddress();

    static string ipv6ToString(in6_addr address);

    static string ipv4ToString(in_addr address);

    static in_addr stringToIpv4(string address);

    static in6_addr stringToIpv6(string address);

    static string formatMacAddress(mac_addr address, MacAddressFormat format);

    /**
     * Inspired by:
     * http://stackoverflow.com/a/20553913/4619907
     *
     * @param address
     * @return
     */
    static mac_addr parseMacAddress(string address);

    static bool isZeroMacAddress(mac_addr address);

    /**
     * NOT MY CODE!!!!
     *
     * source:
     * https://codereview.stackexchange.com/a/78539
     *
     * @param data
     * @param len
     * @return
     */
    static string hexStr(unsigned char *data, int len);
};


#endif //PDS_MITM_UTILS_H
