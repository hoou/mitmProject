include_directories(..)

set(SOURCE_FILES
        main.cpp
        SpoofArguments.cpp
        )

add_executable(pds-spoof ${SOURCE_FILES})

target_link_libraries(pds-spoof ${PCAP_LIBRARIES} ${LIBXML2_LIBRARIES})
