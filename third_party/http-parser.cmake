cmake_minimum_required(VERSION 3.5)
project(http_parser)

set(HTTP_PARSER_SRC ${CMAKE_CURRENT_LIST_DIR}/http-parser/http_parser.c)

include_directories(${CMAKE_CURRENT_LIST_DIR}/http-parser)

set(HTTP_PARSER_LIB http_parser)
add_library(${HTTP_PARSER_LIB} STATIC ${HTTP_PARSER_SRC})

