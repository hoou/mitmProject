#ifndef PROJEKT_NEW_ICMPV6_PACKETMANAGER_H
#define PROJEKT_NEW_ICMPV6_PACKETMANAGER_H


#include "NetworkInterface.h"
#include "PacketManager.h"
#include "ICMPv6_packet.h"

class ICMPv6_packetManager : public PacketManager {
private:
    static ICMPv6_packetManager *instance;

    vector<ICMPv6_packet*> caughtPackets;

    ICMPv6_packetManager();

    void processPacket(u_char *payload, size_t length) override;

public:
    static ICMPv6_packetManager *getInstance();

    void clean() override;

    const vector<ICMPv6_packet *> &getCaughtPackets() const;
};


#endif //PROJEKT_NEW_ICMPV6_PACKETMANAGER_H
