#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>

#include <map>
#include <string>

#define _I(x) std::make_pair(x, #x)
std::map <int, std::string> open_modes
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

char *copybuf;
size_t copybuf_len;
pid_t pid;
std::map<int, std::string> fds;

typedef void (*syscall_handler)(struct user_regs_struct *);

/* Dumps buffers in a manner similar to "hd" on linux */
void hexdump8(const char *tag, const char *buf, size_t cnt) {
    size_t i = 0;
    while (i < cnt) {
        if (tag) {
            printf("%s", tag);
        }

        printf("%08zX  ", i);
        
        // Print the hex first
        for (int j = 0; j < 16; j++) {
            if (i + j < cnt) {
                printf("%02X ", buf[i+j] & 0xFF);
            } else {
                printf("   ");
            }

            if (j == 7) {
                putchar(' ');
            }
        }

        // Now print the string representation
        printf(" [");
        for (int j = 0; j < 16; j++) {
            if (i + j < cnt) {

                if (isgraph(buf[i+j])) {
                    putchar(buf[i+j]);
                } else {
                    putchar('.');
                }
            } else {
                putchar(' ');
            }
        }
        putchar(']');
        putchar('\n');

        i += 16;
    }
}

void hexdump8(char *buf, size_t cnt) {
    hexdump8(NULL, buf, cnt);
}

char *copy_data_from_child(uintptr_t addr, size_t cnt) {
    uint32_t tmp;

    for (size_t i = 0; i < cnt; i += 4) {
        if (i >= copybuf_len) {
            copybuf_len *= 2;
            copybuf = static_cast<char *>(realloc(copybuf, copybuf_len));
        }

        tmp = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        memcpy(copybuf + i, (void *) &tmp, sizeof(tmp));
    }

    return copybuf;
}

char *copy_string_from_child(uintptr_t addr) {
    uint32_t tmp, cnt = 0;

    while (1) {
        if (cnt >= copybuf_len) {
            copybuf_len *= 2;
            copybuf = static_cast<char *>(realloc(copybuf, copybuf_len));
        }

        tmp = ptrace(PTRACE_PEEKDATA, pid, addr + cnt, NULL);
        memcpy(copybuf + cnt, (void *) &tmp, sizeof(tmp));
        if (memchr(&tmp, 0, sizeof(tmp)) != NULL) {
            break;
        }
        cnt += 4;
    }

    return copybuf;
}

void handle_open(struct user_regs_struct *regs) {
    const char *path = copy_string_from_child(regs->rdi);
    uint64_t mode = regs->rsi;
    int64_t ret = regs->rax;
    std::string mode_str;
    
    /* Open has a number of mode flags that can be checked 
     * bitwise, however O_RDONLY is mapped to 0x0. So we need
     * to check whether the mutually exclusive O_WRONLY or O_RDWR
     * are set to decide whether we should assume O_RDONLY is in play
     */
    if (!(mode & O_WRONLY) && !(mode & O_RDWR))
        mode_str += "O_RDONLY";

    for (auto& m : open_modes) {
        if (mode & m.first) {
            if (mode_str != "")
                mode_str += " | ";
            mode_str += m.second;
        }
    }


    printf("open(\"%s\", 0x%08lx '%s') = %ld\n", path, mode, mode_str.c_str(), ret);
    fds[ret] = std::string(path);
}

void handle_close(struct user_regs_struct *regs) {
    int64_t fd = regs->rdi;
    int64_t ret = regs->rax;

    printf("close(%ld '%s') = %ld\n", fd, fds[fd].c_str(), ret);

    if (fd >= 0 && fd <= 2) {
        fds.erase(fd);
    }
}

void handle_read(struct user_regs_struct *regs) {
    int64_t fd = regs->rdi;
    uintptr_t buf = regs->rsi;
    uint64_t len = regs->rdx;
    int64_t ret = regs->rax;

    printf("read(%ld '%s', 0x%016llx, %lu) = %ld\n", fd, fds[fd].c_str(), regs->rsi, len, ret);
    hexdump8("read: ", copy_data_from_child(buf, len), ret);
}

void handle_write(struct user_regs_struct *regs) {
    int64_t fd = regs->rdi;
    uintptr_t buf = regs->rsi;
    uint64_t len = regs->rdx;
    int64_t ret = regs->rax;

    printf("write(%ld \"%s\", 0x%016llx, %lu) = %ld\n", fd, fds[fd].c_str(), regs->rsi, len, ret);
    hexdump8("write: ", copy_data_from_child(buf, ret), ret);
}


int main(int argc, char *argv[]) {
    int status;
    bool in_call = false;
    struct user_regs_struct regs, tmp_regs;
    std::map<int, syscall_handler> handles;

    if (argc < 2)
        return -1;

    // These are often referenced by number rather than name, so map them ahead of time
    fds[0] = std::string("STDIN");
    fds[1] = std::string("STDOUT");
    fds[2] = std::string("STDERR");

    // Set up the syscall mappings to handlers that we care about
    handles[SYS_open] = handle_open;
    handles[SYS_close] = handle_close;
    handles[SYS_read] = handle_read;
    handles[SYS_write] = handle_write;

    // Any copy from the child process is stored here
    copybuf_len = 32;
    copybuf = static_cast<char *>(malloc(copybuf_len));

    pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, pid, NULL, NULL);
        execvp(argv[1], argv + 1);
    } else {
        while (1) {
            wait(&status);
            if (WIFEXITED(status))
                break;

            /* We receive a signal on syscall entry and syscall exit. The two entry points allow us
             * to cache the parameters in the first pass and then the return value in the second
             * pass. From there we can dispatch based on the syscall since we have all the
             * information.
             */
            ptrace(PTRACE_GETREGS, pid, NULL, &tmp_regs);
            if (handles[tmp_regs.orig_rax] != NULL) {
                if (!in_call) {
                    regs = tmp_regs;
                    in_call = true;
                } else {
                    regs.rax = tmp_regs.rax;
                    in_call = false;

                    handles[tmp_regs.orig_rax](&regs);
                }
            }
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        }
    }

    return 0;
}
