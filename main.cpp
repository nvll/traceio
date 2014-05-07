#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

#include <map>
#include <string>

char *copybuf;
size_t copybuf_len;
pid_t pid;

typedef void (*syscall_handler)(struct user_regs_struct *);

/* Dumps buffers in a manner similar to "hd" on linux */
void hexdump8(char *buf, size_t cnt) {
    size_t i = 0;
    while (i < cnt) {
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

void copy_data_from_child(uintptr_t addr, size_t cnt) {
    uint32_t tmp;

    for (size_t i = 0; i < cnt; i += 4) {
        if (i >= copybuf_len) {
            copybuf_len *= 2;
            copybuf = static_cast<char *>(realloc(copybuf, copybuf_len));
        }

        tmp = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
        memcpy(copybuf + i, (void *) &tmp, sizeof(tmp));
    }
}

void copy_string_from_child(uintptr_t addr) {
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
}

void handle_open(struct user_regs_struct *regs) {
    copy_string_from_child(regs->rdi);
    
    printf("open(\"%s\", %u, %u) = %d\n", (const char *) copybuf, regs->rsi, regs->rdx, regs->rax);
}

void handle_close(struct user_regs_struct *regs) {
    printf("close(%d) = %d\n", regs->rdi, regs->rax);
}

void handle_read(struct user_regs_struct *regs) {
    copy_data_from_child(regs->rsi, regs->rdx);

    printf("read(%d, 0x%08X, %zu) = %d\n", regs->rdi, regs->rsi, regs->rdx, regs->rax);
    hexdump8(copybuf, regs->rax);
}

void handle_write(struct user_regs_struct *regs) {
    copy_data_from_child(regs->rsi, regs->rdx);

    printf("write(%d, 0x%08X, %zu) = %d\n", regs->rdi, regs->rsi, regs->rdx, regs->rax);
    hexdump8(copybuf, regs->rax);
}


int main(int argc, char *argv[]) {
    int status;
    bool in_call = false;
    struct user_regs_struct regs, tmp_regs;
    std::map<int, syscall_handler> handles;

    if (argc < 2)
        return -1;

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
