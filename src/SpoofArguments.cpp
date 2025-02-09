#include <getopt.h>
#include <iostream>
#include <sstream>
#include "SpoofArguments.h"

SpoofArguments::SpoofArguments(int argc, char **argv) {
    parse(argc, argv);
    validate();
}

void SpoofArguments::parse(int argc, char **argv) {
    int optionIndex = 0, c = 0, status;
    string tmpAddressString;

    const struct option longOptions[] = {
            {"interface",  required_argument, 0, 'i'},
            {"time",       required_argument, 0, 't'},
            {"protocol",   required_argument, 0, 'p'},
            {"victim1ip",  required_argument, 0, VICTIM1_IP_OPT},
            {"victim1mac", required_argument, 0, VICTIM1_MAC_OPT},
            {"victim2ip",  required_argument, 0, VICTIM2_IP_OPT},
            {"victim2mac", required_argument, 0, VICTIM2_MAC_OPT},
            {NULL, 0,                         0, 0}
    };

    while ((c = getopt_long_only(argc, argv, "", longOptions, &optionIndex)) != -1) {
        switch (c) {
            case 'i':
                interface = optarg;
                iFlag = true;
                break;
            case 't':
                stringstream(optarg) >> time;
                tFlag = true;
                break;
            case 'p':
                protocol = optarg;
                if (protocol == "arp" || protocol == "ndp") {
                    pFlag = true;
                } else {
                    throw InvalidArgumentsException("protocol must be \"arp\" or \"ndp\"");
                }
                break;
            case VICTIM1_IP_OPT:
                tmpAddressString = optarg;

                status = inet_pton(AF_INET, tmpAddressString.c_str(), &victim1Ipv4Address);
                if (status == 1) {
                    victim1Ipv4AddressFlag = true;
                    v1ipFlag = true;
                    break;
                }

                status = inet_pton(AF_INET6, tmpAddressString.c_str(), &victim1Ipv6Address);
                if (status == 1) {
                    victim1Ipv4AddressFlag = false;
                    v1ipFlag = true;
                    break;
                }

                throw InvalidArgumentsException("victim 1 ip address not valid");

            case VICTIM1_MAC_OPT:
                victim1MacAddress = Utils::parseMacAddress(optarg);
                v1macFlag = true;
                break;
            case VICTIM2_IP_OPT:
                tmpAddressString = optarg;

                status = inet_pton(AF_INET, tmpAddressString.c_str(), &victim2Ipv4Address);
                if (status == 1) {
                    victim2Ipv4AddressFlag = true;
                    v2ipFlag = true;
                    break;
                }

                status = inet_pton(AF_INET6, tmpAddressString.c_str(), &victim2Ipv6Address);
                if (status == 1) {
                    victim2Ipv4AddressFlag = false;
                    v2ipFlag = true;
                    break;
                }

                throw InvalidArgumentsException("victim 2 ip address not valid");
            case VICTIM2_MAC_OPT:
                victim2MacAddress = Utils::parseMacAddress(optarg);
                v2macFlag = true;
                break;
            default:
                throw InvalidArgumentsException();
        }
    }
}

void SpoofArguments::validate() {
    if (!iFlag || !tFlag || !pFlag || !v1ipFlag || !v1macFlag || !v2ipFlag || !v2macFlag) {
        throw InvalidArgumentsException("missing required arguments");
    }
    if (protocol == "arp" && (!victim1Ipv4AddressFlag || !victim2Ipv4AddressFlag)) {
        throw InvalidArgumentsException("ARP protocol chosen, expect IPv4 addresses");
    } else if (protocol == "ndp" && (victim1Ipv4AddressFlag || victim2Ipv4AddressFlag)) {
        throw InvalidArgumentsException("NDP protocol chosen, expect IPv6 addresses");
    }
}

const string &SpoofArguments::getInterface() const {
    return interface;
}

unsigned long long int SpoofArguments::getTime() const {
    return time;
}

const string &SpoofArguments::getProtocol() const {
    return protocol;
}

const in_addr &SpoofArguments::getVictim1Ipv4Address() const {
    return victim1Ipv4Address;
}

const in6_addr &SpoofArguments::getVictim1Ipv6Address() const {
    return victim1Ipv6Address;
}

bool SpoofArguments::isVictim1Ipv4Address() const {
    return victim1Ipv4AddressFlag;
}

const mac_addr &SpoofArguments::getVictim1MacAddress() const {
    return victim1MacAddress;
}

const in_addr &SpoofArguments::getVictim2Ipv4Address() const {
    return victim2Ipv4Address;
}

const in6_addr &SpoofArguments::getVictim2Ipv6Address() const {
    return victim2Ipv6Address;
}

bool SpoofArguments::isVictim2Ipv4Address() const {
    return victim2Ipv4AddressFlag;
}

const mac_addr &SpoofArguments::getVictim2MacAddress() const {
    return victim2MacAddress;
}

void SpoofArguments::printUsage() {
    cout << "Usage: ./pds-spoof -i interface -t sec -p protocol -victim1ip ipaddress";
    cout << "-victim1mac macaddress -victim2ip ipaddress -victim2mac macaddress" << endl;
    cout << "Required arguments:" << endl;
    cout << "interface - name of network interface where spoof will be performed" << endl;
    cout << "sec - interval in milliseconds for sending ARP/NDP packets that causes cache poisoning" << endl;
    cout << "protocol - arp or ndp - which protocol to use to poison cache" << endl;
    cout << "ipaddress - IPv4 or IPv6 address of victim" << endl;
    cout << "macaddress - MAC address of victim" << endl;
}
