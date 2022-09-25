cmake_minimum_required(VERSION 3.23)
project(client)

set(CMAKE_CXX_STANDARD 17)

include_directories(/opt/homebrew/Cellar/boost/1.79.0_2/include)

add_executable(client main.cpp Client.cpp Client.h util.cpp util.h)
add_subdirectory(cryptopp_wrapper)
target_link_libraries(client cryptopp_wrapper)