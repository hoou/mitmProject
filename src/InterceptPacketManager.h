#ifndef PDS_MITM_INTERCEPTPACKETMANAGER_H
#define PDS_MITM_INTERCEPTPACKETMANAGER_H


#include "PacketManager.h"

class InterceptPacketManager : public PacketManager<Packet> {
private:
protected:
    void processPacket(u_char *payload, size_t length) override;

public:
    InterceptPacketManager(NetworkInterface &networkInterface);

    InterceptPacketManager(NetworkInterface &networkInterface, const string &listenFilterExpression);
};


#endif //PDS_MITM_INTERCEPTPACKETMANAGER_H
