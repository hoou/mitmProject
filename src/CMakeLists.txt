include_directories(.)

set(SOURCE_FILES
        main.cpp
        Arguments.cpp
        Arguments.h
        ARP_packetManager.cpp
        ARP_packetManager.h
        NetworkInterface.cpp
        NetworkInterface.h
        Subnet.cpp
        Subnet.h
        Utils.cpp
        Utils.h
        ARP_packet.cpp
        ARP_packet.h
        HostsList.cpp
        HostsList.h
        )

add_executable(projekt_new ${SOURCE_FILES})

target_link_libraries(projekt_new ${PCAP_LIBRARIES} ${LIBXML2_LIBRARIES})
