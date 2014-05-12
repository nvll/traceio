#include <fcntl.h>
#include <stdio.h>
#include <map>
#include <vector>
#include <string>

#include "flag_maps.hpp"

#define _E(x) std::make_pair(#x, x)

std::vector<std::pair<std::string, std::map<int, std::string>>> maps {
    _E(open_modes),
    _E(syscall_map),
    _E(mmap_flags),
    _E(mmap_prot),
};

int main (void) {
    for (auto& map : maps) {
        printf("\nFlags for %s\n", map.first.c_str());
        for (auto& m : map.second) {
            printf("0x%08x: %s\n", m.first, m.second.c_str());
        }
    }

    return 0;
}
