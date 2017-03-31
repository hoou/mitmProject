#ifndef PDS_MITM_HOST_H
#define PDS_MITM_HOST_H


#include <set>
#include <ostream>
#include "Utils.h"

class Host {
private:
    mac_addr macAddress;
    set<in_addr> ipv4addresses;
    set<in6_addr> ipv6addresses;

public:
    Host(mac_addr macAddress);

    Host(mac_addr macAddress, set<in_addr> &ipv4addresses, set<in6_addr> &ipv6addresses);

    void addIpv4Address(in_addr address);

    void addIpv6Address(in6_addr address);

    const mac_addr &getMacAddress() const;

    const set<in_addr> &getIpv4addresses() const;

    const set<in6_addr> &getIpv6addresses() const;

    friend ostream &operator<<(ostream &os, const Host &host);
};


#endif //PDS_MITM_HOST_H
