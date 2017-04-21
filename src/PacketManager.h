#ifndef PDS_MITM_PACKETMANAGER_H
#define PDS_MITM_PACKETMANAGER_H


#include <mutex>
#include "NetworkInterface.h"
#include "Packet.h"
#include <thread>
#include <vector>
#include <set>

using namespace std;

/**
 * Packet manager. Class of this template is responsible for sending and receiving packets of specific type
 * @tparam T allowed types of packet: generic Packet, ICMPv6 Packet, ARP packet
 */
template<typename T>
class PacketManager {
private:
    static vector<PacketManager *> instances;
    pcap_t *sendPCAP_handle;
    pcap_t *listenPCAP_handle;

    mutex mtx;
    static mutex setupFilterMtx;
    thread listenThread;

    string listenFilterExpression;

    vector<Packet *> caughtPackets;

    /**
     * Task responsible for capturing packets
     */
    void listenTask();

    /**
     * Compile and setup filter for capturing packets
     */
    void setupFilters();

    /**
     * Handle captured packet
     * @param args optional arguments
     * @param header information about length of capture packet etc.
     * @param payload packet raw data
     */
    static void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *payload);

    /**
     * Close senging pcap handler and delete all caught/captured packets
     */
    void clean();

protected:
    NetworkInterface &networkInterface;

    /**
     * Process caught/captured packet
     * @param payload
     * @param length
     */
    virtual void processPacket(u_char *payload, size_t length);

public:

    /**
     * Construct packet manager and prepare it for sending packets
     * @param networkInterface network device to work with
     */
    PacketManager(NetworkInterface &networkInterface);

    /**
     * Construct packet manager, setup filter for capturing packets and prepare it for sending packets
     * @param networkInterface network device to work with
     * @param listenFilterExpression filter for capturing packets
     */
    PacketManager(NetworkInterface &networkInterface, string listenFilterExpression);

    virtual ~PacketManager();

    void setListenFilterExpression(const string &listenFilterExpression);

    /**
     * Create new thread with listen task
     */
    void listen();

    /**
     * Stop capturing packets
     */
    void stopListen();

    /**
     * Send packet
     * @param packet
     */
    void send(Packet *packet);

    /**
     * Wait for listening thread to finish
     */
    void wait();

    const vector<Packet *> &getCaughtPackets();

    static const vector<PacketManager *> &getInstances();

    static string createHostFilter(string target, string separator, set<pair<in_addr, Subnet>> addresses);

    static string createHostFilter(string target, string separator, set<in6_addr> addresses);

    static string createSrcFilter(set<pair<in_addr, Subnet>> addresses);

    static string createSrcFilter(set<in6_addr> addresses);

    static string createDstFilter(set<pair<in_addr, Subnet>> addresses);

    static string createDstFilter(set<in6_addr> addresses);
};


#endif //PDS_MITM_PACKETMANAGER_H
