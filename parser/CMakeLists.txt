add_library(parser certificate_parser.cpp)
include_directories(${CMAKE_SOURCE_DIR}/parser)

install(TARGETS parser LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
