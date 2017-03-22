#ifndef PROJEKT_NEW_INTERFACEINFORMATION_H
#define PROJEKT_NEW_INTERFACEINFORMATION_H

#include <string>
#include <pcap.h>
#include <linux/if_ether.h>
#include <vector>
#include <array>
#include "Subnet.h"

using namespace std;

class NetworkInterface {
private:
    string name;
    in_addr address;
    array<u_int8_t, ETH_ALEN> physicalAddress;
    Subnet *subnet = nullptr;

    in_addr setAddressAndGetMask();

    void setPhysicalAddress();

public:
    NetworkInterface(const string &name);

    virtual ~NetworkInterface();

    void print();

    const in_addr &getAddress() const;

    const array<u_int8_t, (size_t) ETH_ALEN> &getPhysicalAddress() const;

    const string &getName() const;

    Subnet *getSubnet() const;
};


#endif //PROJEKT_NEW_INTERFACEINFORMATION_H
