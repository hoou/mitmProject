#ifndef PROJEKT_NEW_ICMPV6_PACKETMANAGER_H
#define PROJEKT_NEW_ICMPV6_PACKETMANAGER_H


#include "NetworkInterface.h"

class ICMPv6_packetManager {
private:
    static NetworkInterface *networkInterface;
public:
    static void init(NetworkInterface *networkInterface);
};


#endif //PROJEKT_NEW_ICMPV6_PACKETMANAGER_H
