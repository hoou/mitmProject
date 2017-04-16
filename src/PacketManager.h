#ifndef PROJEKT_NEW_PACKETMANAGER_H
#define PROJEKT_NEW_PACKETMANAGER_H


#include <mutex>
#include "NetworkInterface.h"
#include "Packet.h"
#include <thread>
#include <vector>
#include <set>

using namespace std;

template<typename T>
class PacketManager {
private:
    static vector<PacketManager *> instances;
    pcap_t *sendPCAP_handle;

    mutex mtx;
    thread listenThread;
    string listenFilterExpression;

    vector<Packet *> caughtPackets;

    void listenTask();

    void setupFilters();

    static void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *payload);

    pcap_t *listenPCAP_handle;

    void clean();

protected:
    NetworkInterface &networkInterface;

    virtual void processPacket(u_char *payload, size_t length);

public:

    PacketManager(NetworkInterface &networkInterface);

    PacketManager(NetworkInterface &networkInterface, string listenFilterExpression);

    virtual ~PacketManager();

    void setListenFilterExpression(const string &listenFilterExpression);

    void listen();

    void stopListen();

    void send(Packet *packet);

    void wait();

    const vector<Packet *> &getCaughtPackets();

    static const vector<PacketManager *> &getInstances();

    static string createHostFilter(string target, string separator, vector<in_addr> addresses);

    static string createHostFilter(string target, string separator, vector<in6_addr> addresses);

    static string createSrcFilter(vector<in_addr> addresses);

    static string createSrcFilter(vector<in6_addr> addresses);

    static string createDstFilter(vector<in_addr> addresses);

    static string createDstFilter(vector<in6_addr> addresses);
};


#endif //PROJEKT_NEW_PACKETMANAGER_H
