cmake_minimum_required (VERSION 3.12)
project (X509Parser)

message(${CMAKE_SOURCE_DIR})
set(CMAKE_CXX_STANDARD 11)
#set (CMAKE_REQUIRED_LIBRARIES $(CMAKE_REQUIRED_LIBRARIES) -lc++)

#version number
set (LameEncoderProject_VERSION_MAJOR 1)
set (LameEncoderProject_VERSION_MINOR 0)

#include the subdirectory containing our source files
add_subdirectory (parser)
include_directories(${CMAKE_SOURCE_DIR}/parser)
include_directories(${CMAKE_SOURCE_DIR}/misc_include)

add_executable (X509Parser main.cpp)

add_library(cryptopp  STATIC IMPORTED)
if (UNIX)
    set_target_properties(cryptopp  PROPERTIES
     IMPORTED_LOCATION "/usr/local/lib/libcryptopp.a"
      INTERFACE_INCLUDE_DIRECTORIES "/usr/local/include/crpyptopp/"
    )
endif(UNIX)

if(WIN32)
    #FIND_LIBRARY(libcryptopp /usr/local/lib/libcryptopp.a)
endif(WIN32)


target_link_libraries (X509Parser parser cryptopp)

install (TARGETS X509Parser DESTINATION bin)
