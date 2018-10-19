cmake_minimum_required(VERSION 3.12.3)
project(RechnernetzPraxis)

include(FindPCAP.cmake)

add_executable(rechnernetz_praxis main.cpp)
target_link_libraries(rechnernetz_praxis ${PCAP_LIBRARY})
