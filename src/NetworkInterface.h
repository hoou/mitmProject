#ifndef PDS_MITM_INTERFACEINFORMATION_H
#define PDS_MITM_INTERFACEINFORMATION_H

#include <string>
#include <pcap.h>
#include <linux/if_ether.h>
#include <vector>
#include <array>
#include "Utils.h"
#include "Subnet.h"
#include "Host.h"

using namespace std;

/**
 * Network interface
 */
class NetworkInterface {
private:
    string name;
    Host *host = nullptr;

    /**
     * Retrieve all IPv4 and IPv6 addresses of network interface with given name
     *
     * @param name network interface name
     * @param host pointer to Host object, where all found addresses will be added
     */
    static void retrieveAddressesByName(string name, Host *host);

    /**
     * Retrieve MAC address of network interface with given name
     * @param name network interface name
     * @return found MAC address
     */
    static mac_addr retrievePhysicalAddress(string name);

public:
    /**
     * Construct NetworkInterface object with given name and try to retrieve all necessary information
     * such as IPv4 and IPv6 addresses and MAC address
     * @param name network interface name
     */
    NetworkInterface(const string &name);

    /**
     * NetworkInterface destructor. Deletes Host object.
     */
    virtual ~NetworkInterface();

    const string &getName() const;

    Host *getHost() const;
};


#endif //PDS_MITM_INTERFACEINFORMATION_H
