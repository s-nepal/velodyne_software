cmake_minimum_required(VERSION 2.8 FATAL_ERROR)
project(packet_capture)

##Compiler flags

if(CMAKE_COMPILER_IS_GNUCXX)
	set(CMAKE_CXX_FLAGS "-O3")
	set(CMAKE_EXE_LINKER_FLAGS "-s")
endif()

find_package(PCL 1.2 REQUIRED)
find_package(OpenCV REQUIRED)

include_directories(${PCL_INCLUDE_DIRS} "/usr/include/pcap/")
link_directories(${PCL_LIBRARY_DIRS})
add_definitions(${PCL_DEFINITIONS})
include_directories(${PCAP_INCLUDE_DIRS})

include_directories( ${OpenCV_INCLUDE_DIRS})

add_executable (packet_capture packet_capture.cpp)
target_link_libraries (packet_capture ${PCL_LIBRARIES} "pcap" ${OpenCV_LIBS} "pthread")
target_compile_features(packet_capture PRIVATE cxx_range_for)

