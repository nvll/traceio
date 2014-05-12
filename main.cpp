#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
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

#include "flag_maps.hpp"

char *copybuf;
size_t copybuf_len;
pid_t pid;
std::map<int, std::string> fds;

typedef void (*syscall_handler)(struct user_regs_struct *);

void map_flags(uint64_t flags, std::map<int, std::string>& map, std::string& str) {
    for (auto& m : map) {
        if (flags & m.first) {
            if (str != "") {
                str += " | ";
            }

            str += m.second;
        }
    }
}

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

void handle_creat(struct user_regs_struct *regs) {
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

    map_flags(mode, open_modes, mode_str);

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

void handle_mmap(struct user_regs_struct *regs) {
    uintptr_t addr = regs->rdi;
    uint64_t length = regs->rsi;
    int64_t prot = regs->rdx;
    int64_t flags = regs->r10;
    int64_t fd = (flags & MAP_ANONYMOUS) ? -1 : regs->r8;
    off_t offset = regs->r9;
    uintptr_t ret = regs->rax;
    std::string flags_str;
    std::string prot_str;
    
    map_flags(flags, mmap_flags, flags_str);
    map_flags(prot, mmap_prot, prot_str);
    printf("mmap(0x%016llx, %lu, 0x%08lx '%s', 0x%08lx '%s', %ld, %ld) = 0x%016lx\n",
        addr, length, prot, prot_str.c_str(), flags, flags_str.c_str(), fd, offset, ret);
}

void handle_unhandled_syscall(struct user_regs_struct *regs) {
    int64_t syscall = regs->orig_rax;
    uint64_t ret = regs->rax;
    printf("%s(...?) = 0x%016lx\n", syscall_map[syscall].c_str(), ret);
}
    
int main(int argc, char *argv[]) {
    int status;
    bool in_call = false;
    struct user_regs_struct regs, tmp_regs;
    std::map<int, syscall_handler> handles;
    bool show_unhandled_syscalls = getenv("SHOW_UNHANDLED_SYSCALLS");
    int64_t current_syscall;

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
    handles[SYS_mmap] = handle_mmap;

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
            if (!in_call) {
                regs = tmp_regs;
                in_call = true;
                
            } else {
                in_call = false;

                if (handles[regs.orig_rax]) {
                    handles[regs.orig_rax](&regs);
                } else if (show_unhandled_syscalls) {
                    handle_unhandled_syscall(&regs);
                }
            }
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        }
    }

    return 0;
}
