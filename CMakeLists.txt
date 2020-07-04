cmake_minimum_required(VERSION 3.4)
project(kproxy)

# export compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS "-g ${CMAKE_CXX_FLAGS}")
set(CMAKE_C_FLAGS   "-g ${CMAKE_C_FLAGS}")

set(kproxy_server kproxys)
set(kproxy_client kproxy)

set(kproxy_lib kpx)
set(kproxy_lib_src 
    lib/kserver_libuv.cpp
    lib/kserver_server.cpp
    lib/kserver_server2net.cpp
    lib/kserver_multiplexer.cpp
    lib/kserver_config.cpp

    lib/stream.cpp
    lib/stream_libuv.cpp
    lib/stream_memory.cpp

    lib/file_libuv.cpp
    lib/config_file.cpp

    lib/kclient_relay.cpp
    lib/kclient_server.cpp
    lib/kclient_socks5.cpp
    lib/kclient_clientproxy.cpp
    lib/kclient_multiplexer.cpp
    lib/kclient_config.cpp

    lib/kpacket.cpp
    lib/socks5.cpp

    lib/logger.cpp

    lib/events.cpp
    lib/readonly_buf.cpp
    lib/ObjectFactory.cpp
    lib/object_manager.cpp

    lib/utils.cpp
    lib/utils_hideuv.cpp
    lib/libuv_utils.cpp

    lib/tcpabstraction.cpp
    lib/websocket.cpp
    lib/websocket_libuv.cpp
    lib/http.cpp
    )

include_directories("${CMAKE_CURRENT_LIST_DIR}/include")

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

set(JSON_BuildTests OFF CACHE INTERNAL "")
add_subdirectory(./third_party/json)

include(${CMAKE_CURRENT_LIST_DIR}/third_party/http-parser.cmake)
# include(${CMAKE_CURRENT_LIST_DIR}/third_party/imgui.cmake)

# library #{
add_library(${kproxy_lib} STATIC ${kproxy_lib_src})

add_dependencies(${kproxy_lib} uv_a)
add_dependencies(${kproxy_lib} nlohmann_json)
add_dependencies(${kproxy_lib} ${HTTP_PARSER_LIB})
target_link_libraries(${kproxy_lib} uv_a)
target_link_libraries(${kproxy_lib} nlohmann_json)
target_link_libraries(${kproxy_lib} ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(${kproxy_lib} ${OPENSSL_SSL_LIBRARY})
target_link_libraries(${kproxy_lib} ${HTTP_PARSER_LIB})
#}

# server #{
add_executable(${kproxy_server} ./src/main.cpp)

add_dependencies(${kproxy_server} uv_a)
target_link_libraries(${kproxy_server} uv_a)

target_link_libraries(${kproxy_server} ${kproxy_lib})
target_link_libraries(${kproxy_server} ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(${kproxy_server} ${OPENSSL_SSL_LIBRARY})
#}

# client #{
add_executable(${kproxy_client} ./app/main.cpp)

add_dependencies(${kproxy_client} uv_a)
target_link_libraries(${kproxy_client} uv_a)

target_link_libraries(${kproxy_client} ${kproxy_lib})
target_link_libraries(${kproxy_client} ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(${kproxy_client} ${OPENSSL_SSL_LIBRARY})
#}

# test #{
file(GLOB TEST_FILES_CPP "${CMAKE_CURRENT_LIST_DIR}/tests/test-*.cpp")
file(GLOB TEST_FILES_CX  "${CMAKE_CURRENT_LIST_DIR}/tests/test-*.cx")
file(GLOB TEST_FILES     "${CMAKE_CURRENT_LIST_DIR}/tests/test-*.c")
list(APPEND TEST_FILES ${TEST_FILES_CPP} ${TEST_FILES_CX})
foreach (test_file IN LISTS TEST_FILES)
    get_filename_component(fname ${test_file} NAME_WE)
    string(LENGTH ${fname} fname_len)
    math(EXPR name_len "${fname_len} - 5")
    string(SUBSTRING ${fname} 5 ${name_len} execname)
    message(STATUS "test=${execname}")
    add_executable(${execname} ${test_file})
    add_dependencies(${execname} ${kproxy_lib})
    target_link_libraries(${execname} ${kproxy_lib})
    set_target_properties(${execname} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
endforeach()
#}

