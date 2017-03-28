#ifndef PROJEKT_NEW_SUBNET_H
#define PROJEKT_NEW_SUBNET_H

#include <string>
#include <arpa/inet.h>
#include <vector>

using namespace std;

class Subnet {
private:
    in_addr address;
    in_addr mask;
    in_addr firstAvailableHostAddress;
    in_addr lastAvailableHostAddress;
    in_addr broadcastAddress;
    unsigned long long numberOfAvailableHosts;

public:
    Subnet(const in_addr &address, const in_addr &mask);

    vector<in_addr> getAllPossibleHostAddresses();

    const in_addr &getAddress() const;

    const in_addr &getMask() const;

    const in_addr &getFirstAvailableHostAddress() const;

    const in_addr &getLastAvailableHostAddress() const;

    const in_addr &getBroadcastAddress() const;

    unsigned long long int getNumberOfAvailableHosts() const;

    void print();
};


#endif //PROJEKT_NEW_SUBNET_H
