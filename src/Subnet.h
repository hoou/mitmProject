#ifndef PDS_MITM_SUBNET_H
#define PDS_MITM_SUBNET_H

#include <string>
#include <arpa/inet.h>
#include <vector>

using namespace std;

/**
 * Network subnet
 */
class Subnet {
private:
    in_addr address;
    in_addr mask;
    in_addr firstAvailableHostAddress;
    in_addr lastAvailableHostAddress;
    in_addr broadcastAddress;
    unsigned long long numberOfAvailableHosts;

public:
    /**
     * Construct subnet with given IPv4 address and netmask and calculate all necessary addresses and numbers
     * such as broadcast address, number of available hosts etc.
     *
     * @param address
     * @param mask
     */
    Subnet(const in_addr &address, const in_addr &mask);

    vector<in_addr> getAllPossibleHostAddresses() const;

    const in_addr &getAddress() const;

    const in_addr &getMask() const;

    const in_addr &getFirstAvailableHostAddress() const;

    const in_addr &getLastAvailableHostAddress() const;

    const in_addr &getBroadcastAddress() const;

    unsigned long long int getNumberOfAvailableHosts() const;

    /**
     * Print subnet information
     */
    void print();
};


#endif //PDS_MITM_SUBNET_H
