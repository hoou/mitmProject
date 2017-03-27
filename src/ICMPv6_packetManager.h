#ifndef PROJEKT_NEW_ICMPV6_PACKETMANAGER_H
#define PROJEKT_NEW_ICMPV6_PACKETMANAGER_H


#include "NetworkInterface.h"
#include "PacketManager.h"

class ICMPv6_packetManager : public PacketManager {
private:
    static ICMPv6_packetManager *instance;

    ICMPv6_packetManager();

    void processPacket(u_char *payload) override;

public:
    void clean() override;

    static ICMPv6_packetManager *getInstance();
};


#endif //PROJEKT_NEW_ICMPV6_PACKETMANAGER_H
