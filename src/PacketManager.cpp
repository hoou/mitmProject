#include <thread>
#include <iostream>
#include "PacketManager.h"

void PacketManager::init(NetworkInterface *networkInterface) {
    this->networkInterface = networkInterface;

    /* Initialize pcap handle for sending packets */
    char errorBuffer[PCAP_ERRBUF_SIZE];
    sendPCAP_handle = pcap_open_live(networkInterface->getName().c_str(), 96, 1, 0, errorBuffer);
    if (sendPCAP_handle == NULL)
        throw runtime_error(errorBuffer);
}

void PacketManager::clean() {
    if (sendPCAP_handle != nullptr && sendPCAP_handle != NULL) {
        pcap_close(sendPCAP_handle);
    }
}

void PacketManager::listen() {
    mtx.lock();
    listenThread = thread(&PacketManager::listenTask, this);
}

void PacketManager::listenTask() {
    char errorBuffer[PCAP_ERRBUF_SIZE];

    listenPCAP_handle = pcap_open_live(networkInterface->getName().c_str(), 1024, 0, 1000, errorBuffer);
    if (listenPCAP_handle == NULL) {
        throw runtime_error(errorBuffer);
    }

    setupFilters();

    /* Allow to send packets */
    mtx.unlock();

    pcap_loop(listenPCAP_handle, 0, packetHandler, reinterpret_cast<u_char *>(this));
    pcap_close(listenPCAP_handle);
}

void PacketManager::packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *payload) {
    PacketManager *packetManager = reinterpret_cast<PacketManager *>(args);
    packetManager->processPacket((u_char *) payload);
}

void PacketManager::stopListen() {
    pcap_breakloop(listenPCAP_handle);
}

void PacketManager::wait() {
    listenThread.join();
}

void PacketManager::send(Packet *packet) {
    int status;

    /* Wait for beginning of pcap_loop */
    mtx.lock();

    status = pcap_inject(sendPCAP_handle, packet->getRawData(), packet->getLength());

    if (status == -1)
        throw runtime_error(pcap_geterr(sendPCAP_handle));

    mtx.unlock();

}

void PacketManager::setupFilters() {
    int status;
    struct bpf_program filter;

    /* no filter */
    if (listenFilterExpression.empty())
        return;

    status = pcap_compile(listenPCAP_handle, &filter, listenFilterExpression.c_str(), 0, 0);
    if (status == -1) {
        throw runtime_error(pcap_geterr(listenPCAP_handle));
    }

    status = pcap_setfilter(listenPCAP_handle, &filter);
    if (status == -1)
        throw runtime_error(pcap_geterr(listenPCAP_handle));

    pcap_freecode(&filter);
}

void PacketManager::setListenFilterExpression(const string &listenFilterExpression) {
    PacketManager::listenFilterExpression = listenFilterExpression;
}
