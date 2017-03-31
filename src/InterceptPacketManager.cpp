#include "InterceptPacketManager.h"

InterceptPacketManager::InterceptPacketManager(NetworkInterface &networkInterface) : PacketManager(networkInterface) {}

InterceptPacketManager::InterceptPacketManager(NetworkInterface &networkInterface, const string &listenFilterExpression)
        : PacketManager(networkInterface, listenFilterExpression) {}

void InterceptPacketManager::processPacket(u_char *payload, size_t length) {
    Packet packet(payload, length);

}
