#ifndef PDS_MITM_HOST_H
#define PDS_MITM_HOST_H


#include <set>
#include <ostream>
#include "Utils.h"
#include "Subnet.h"

class Host {
private:
    mac_addr macAddress;
    set<pair<in_addr, Subnet>> ipv4addresses;
    set<in6_addr> ipv6addresses;
    string group;

public:
    Host(mac_addr macAddress);

    Host(mac_addr macAddress, set<pair<in_addr, Subnet>> &ipv4addresses, set<in6_addr> &ipv6addresses);

    void addIpv4Address(in_addr address, in_addr mask);

    void addIpv6Address(in6_addr address);

    const mac_addr &getMacAddress() const;

    const set<pair<in_addr, Subnet>> &getIpv4addresses() const;

    const set<in6_addr> &getIpv6addresses() const;

    const string &getGroupName() const;

    void setGroup(const string &group);

    friend ostream &operator<<(ostream &os, const Host &host);
};


#endif //PDS_MITM_HOST_H
