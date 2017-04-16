#ifndef PROJEKT_NEW_INTERFACEINFORMATION_H
#define PROJEKT_NEW_INTERFACEINFORMATION_H

#include <string>
#include <pcap.h>
#include <linux/if_ether.h>
#include <vector>
#include <array>
#include "Utils.h"
#include "Subnet.h"
#include "Host.h"

using namespace std;

class NetworkInterface {
private:
    string name;
    Host *host = nullptr;

    static void retrieveAddressesByName(string name, Host *host);

    static mac_addr retrievePhysicalAddress(string name);

public:
    NetworkInterface(const string &name);

    virtual ~NetworkInterface();

    const string &getName() const;

    Host *getHost() const;
};


#endif //PROJEKT_NEW_INTERFACEINFORMATION_H
