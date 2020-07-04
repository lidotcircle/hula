#include "../include/duplex_map.hpp"

#include <string>
#include <iostream>

int main() {
    DuplexMap<std::string, int> dm;
    dm[0] = "hello";
    dm["good"] = 100;
    dm["hello"] = 200;

    assert(dm.size() == 2);
    dm[2] = "enheng";

    dm.erase(dm.find(200));
    dm[200] = "haha";
    assert(dm.size() == 3);

    assert(dm.find(200) != dm.end());
    assert(dm.find(199) == dm.end());
    assert(dm.find("haha") != dm.end());
    assert(dm.find("world") == dm.end());

    for(auto& x: dm)
        std::cout << x.first << "  " << x.second << std::endl;

    return 0;
}

