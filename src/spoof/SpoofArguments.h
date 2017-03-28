#ifndef PDS_MITM_SPOOFPARSER_H
#define PDS_MITM_SPOOFPARSER_H

#define VICTIM1_IP_OPT 1000
#define VICTIM1_MAC_OPT 1001
#define VICTIM2_IP_OPT 1002
#define VICTIM2_MAC_OPT 1003

#include "Utils.h"
#include <netinet/ip.h>

using namespace std;

class InvalidArgumentsException : public runtime_error {
public:
    InvalidArgumentsException();

    InvalidArgumentsException(const string &__arg);
};

class SpoofArguments {
private:
    string interface;
    unsigned long long time;
    string protocol;

    in_addr victim1Ipv4Address;
    in6_addr victim1Ipv6Address;
    bool victim1Ipv4AddressFlag;
    mac_addr victim1MacAddress;

    in_addr victim2Ipv4Address;
    in6_addr victim2Ipv6Address;
    bool victim2Ipv4AddressFlag;
    mac_addr victim2MacAddress;

    bool iFlag = false;
    bool tFlag = false;
    bool pFlag = false;
    bool v1ipFlag = false;
    bool v1macFlag = false;
    bool v2ipFlag = false;
    bool v2macFlag = false;

    void parse(int argc, char **argv);

public:
    SpoofArguments(int argc, char **argv);

    static void printUsage();

    const string &getInterface() const;

    unsigned long long int getTime() const;

    const string &getProtocol() const;

    const in_addr &getVictim1Ipv4Address() const;

    const in6_addr &getVictim1Ipv6Address() const;

    bool isVictim1Ipv4Address() const;

    const mac_addr &getVictim1MacAddress() const;

    const in_addr &getVictim2Ipv4Address() const;

    const in6_addr &getVictim2Ipv6Address() const;

    bool isVictim2Ipv4Address() const;

    const mac_addr &getVictim2MacAddress() const;

};


#endif //PDS_MITM_SPOOFPARSER_H
