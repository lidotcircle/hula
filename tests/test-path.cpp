#include <iostream>
#include <filesystem>

#include <chrono>
#include "../include/utils.h"


int main() {
    std::filesystem::path p = "/hello.cpp";
    std::cout << p.extension() << std::endl;
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::cout << time_t_to_UTCString(now) << std::endl;
}

