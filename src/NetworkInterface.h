#ifndef PROJEKT_NEW_INTERFACEINFORMATION_H
#define PROJEKT_NEW_INTERFACEINFORMATION_H

#include <string>
#include <pcap.h>
#include <linux/if_ether.h>
#include <vector>
#include "Subnet.h"

using namespace std;

class NetworkInterface {
private:
    string name;
    in_addr address;
    u_int8_t physicalAddress[ETH_ALEN];
    Subnet *subnet = nullptr;

    in_addr setAddressAndGetMask();

    void setPhysicalAddress();

public:
    NetworkInterface(const string &name);

    virtual ~NetworkInterface();

    void print();

    const in_addr &getAddress() const;

    const u_int8_t *getPhysicalAddress() const;

    const string &getName() const;

    Subnet *getSubnet() const;
};


#endif //PROJEKT_NEW_INTERFACEINFORMATION_H
