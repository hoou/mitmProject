include_directories(.)

set(SCANNER_SOURCE_FILES
        scanner.cpp
        ScannerArguments.cpp
        NetworkInterface.cpp
        Subnet.cpp
        Utils.cpp
        ARP_packet.cpp
        HostsList.cpp
        PacketManager.cpp
        Packet.cpp
        ICMPv6_packet.cpp
        IPv6_packet.cpp
        Host.cpp
        Group.cpp
        )

set(SPOOF_SOURCE_FILES
        spoof.cpp
        SpoofArguments.cpp
        Utils.cpp
        NetworkInterface.cpp
        ARP_packet.cpp
        PacketManager.cpp
        Packet.cpp
        Subnet.cpp
        ICMPv6_packet.cpp
        IPv6_packet.cpp
        )

set(INTERCEPT_SOURCE_FILES
        intercept.cpp
        ScannerArguments.cpp
        NetworkInterface.cpp
        Packet.cpp
        PacketManager.cpp
        Utils.cpp
        Subnet.cpp
        ARP_packet.cpp
        ICMPv6_packet.cpp
        IPv6_packet.cpp
        InterceptPacketManager.cpp
        Host.cpp
        HostsList.cpp
        Group.cpp
        )

add_executable(pds-scanner ${SCANNER_SOURCE_FILES})

add_executable(pds-spoof ${SPOOF_SOURCE_FILES})

add_executable(pds-intercept ${INTERCEPT_SOURCE_FILES})

target_link_libraries(pds-scanner ${PCAP_LIBRARIES} ${LIBXML2_LIBRARIES})

target_link_libraries(pds-spoof ${PCAP_LIBRARIES})

target_link_libraries(pds-intercept ${PCAP_LIBRARIES} ${LIBXML2_LIBRARIES})
