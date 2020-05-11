cmake_minimum_required(VERSION 3.4)
project(kproxy)

# export compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(kproxy_server kproxys)
set(kproxy_client kproxy)

# openssl #{
if (WIN32)
    set(OPENSSL_PATH ./third_party/openssl)
    find_file(OPENSSL_INCLUDE_SSL_H NAME ssl.h PATH_SUFFIXES include/openssl HINTS ${OPENSSL_PATH})
    find_library(OPENSSL_CRYPTO_LIBRARY NAME libeay32 PATH_SUFFIXES lib HINTS ${OPENSSL_PATH})
    find_library(OPENSSL_SSL_LIBRARY    NAME ssleay32 PATH_SUFFIXES lib HINTS ${OPENSSL_PATH})
    get_filename_component(OPENSSL_INCLUDE_DIR_ ${OPENSSL_INCLUDE_SSL_H} DIRECTORY)
    get_filename_component(OPENSSL_INCLUDE_DIR  ${OPENSSL_INCLUDE_DIR_}  DIRECTORY)
else()
    find_package(OpenSSL)
endif()
include_directories(${OPENSSL_INCLUDE_DIR})
#}

add_subdirectory(./third_party/libuv)

add_executable(${kproxy_server} ./src/main.cpp)

add_dependencies(${kproxy_server} uv_a)
target_link_libraries(${kproxy_server} uv_a)

target_link_libraries(${kproxy_server} ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(${kproxy_server} ${OPENSSL_SSL_LIBRARY})

