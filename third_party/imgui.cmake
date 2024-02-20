cmake_minimum_required(VERSION 3.5)
project(imgui)

set(GL3W_DIR "${CMAKE_CURRENT_LIST_DIR}/imgui/examples/libs/gl3w")
include_directories(${GL3W_DIR})
file(GLOB GL3W_SRC "${GL3W_DIR}/GL/*.c")

include_directories(${CMAKE_CURRENT_LIST_DIR}/imgui)

file(GLOB IMGUI_SRC "${CMAKE_CURRENT_LIST_DIR}/imgui/*.cpp")
set(IMGUI_IMPL_SRC 
    ${CMAKE_CURRENT_LIST_DIR}/imgui/examples/imgui_impl_glfw.cpp
    ${CMAKE_CURRENT_LIST_DIR}/imgui/examples/imgui_impl_opengl3.cpp)

set(IMGUI_LIBRARY imgui)
add_library(${IMGUI_LIBRARY} STATIC ${IMGUI_SRC} ${IMGUI_IMPL_SRC} ${GL3W_SRC})

# GLFW Setup #{
if (WIN32)
    set(GLFW_PATH third_party/glfw)
    find_file(GLFW_INCLUDE_FILE NAME glfw3.h PATH_SUFFIXES include/GLFW HINTS ${GLFW_PATH})
    find_library(glfw NAME glfw3 HINTS ${GLFW_PATH})
    get_filename_component(GLFW_INCLUDE_DIR    ${GLFW_INCLUDE_FILE} DIRECTORY)
    get_filename_component(GLFW_INCLUDE_DIR_EX ${GLFW_INCLUDE_DIR}  DIRECTORY)
    include_directories(${GLFW_INCLUDE_DIR_EX})
    message("-- Found glfw: " ${glfw})
    set(glfw_target ${glfw})
else()
    find_package (glfw3 REQUIRED)
    if (glfw3_FOUND)
        message("-- Found glfw")
    else()
        message(FATAL_ERROR "cannot found glfw")
    endif()
    set(glfw_target glfw)
endif()
#}

include (FindOpenGL)
target_link_libraries(${IMGUI_LIBRARY} ${OPENGL_LIBRARIES})
target_link_libraries(${IMGUI_LIBRARY} ${glfw_target})

