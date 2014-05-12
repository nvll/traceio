#include <fcntl.h>
#include <stdio.h>
#include <map>

#define _I(x) std::make_pair(x, #x)
std::map <int, std::string> modes
{
    _I(O_RDONLY),
    _I(O_WRONLY),
    _I(O_RDWR),
    _I(O_CREAT),
    _I(O_APPEND),
    _I(O_ASYNC),
    _I(O_CLOEXEC),
    _I(O_DIRECT),
    _I(O_DIRECTORY),
    _I(O_EXCL),
    _I(O_LARGEFILE),
    _I(O_NOATIME),
    _I(O_NOCTTY),
    _I(O_NOFOLLOW),
    _I(O_NONBLOCK),
    _I(O_NDELAY),
    _I(O_PATH),
    _I(O_SYNC),
    _I(O_TRUNC),
};
#undef _I

int main (void) {
    for (auto& i : modes) {
        printf("0x%08x: %s\n", i.first, i.second.c_str());
    }

    return 0;
}
