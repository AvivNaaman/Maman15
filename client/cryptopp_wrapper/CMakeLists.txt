
set(CMAKE_CXX_STANDARD 17)
cmake_minimum_required(VERSION 3.23)

add_library(cryptopp_wrapper AESWrapper.cpp AESWrapper.h Base64Wrapper.cpp Base64Wrapper.h RSAWrapper.cpp RSAWrapper.h)
#add_executable(cryptopp_wrapper AESWrapper.cpp AESWrapper.h Base64Wrapper.cpp Base64Wrapper.h RSAWrapper.cpp RSAWrapper.h)
include_directories(cryptopp_wrapper /Users/avivnaaman/cryptoppgit/cryptopp)
target_link_libraries(cryptopp_wrapper STATIC /Users/avivnaaman/cryptoppgit/cryptopp/libcryptopp.a)