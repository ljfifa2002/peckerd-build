#include "ptrace_arm64.h"
#include "../common/log.h"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <fcntl.h>
#include <unistd.h>

long xptrace(int request, ...) {
    va_list args;
    va_start(args, request);

    pid_t pid = va_arg(args, pid_t);
    void* addr = va_arg(args, void*);
    void* data = va_arg(args, void*);

    errno = 0;
    long result = ptrace(request, pid, addr, data);

    va_end(args);

    if (result == -1 && errno != 0) {
        LOGE("ptrace failed: request=%d pid=%d errno=%d (%s)",
             request, pid, errno, strerror(errno));
    }

    return result;
}

bool attach_process(pid_t pid) {
    if (pid <= 0) {
        LOGE("attach_process: invalid pid=%d", pid);
        return false;
    }

    if (xptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
        LOGE("attach_process: PTRACE_ATTACH failed, pid=%d", pid);
        return false;
    }

    int status = 0;
    if (waitpid(pid, &status, WUNTRACED) == -1) {
        LOGE("attach_process: waitpid failed, pid=%d errno=%d (%s)",
             pid, errno, strerror(errno));
        return false;
    }

    LOGI("attach_process: attached to pid=%d status=0x%x", pid, status);
    return true;
}

bool detach_process(pid_t pid) {
    if (pid <= 0) {
        LOGE("detach_process: invalid pid=%d", pid);
        return false;
    }

    if (xptrace(PTRACE_DETACH, pid, nullptr, nullptr) == -1) {
        LOGE("detach_process: PTRACE_DETACH failed, pid=%d", pid);
        return false;
    }

    LOGI("detach_process: detached from pid=%d", pid);
    return true;
}

// mem_rw: read or write target process memory via /proc/<pid>/mem.
// PTRACE_PEEKDATA/POKEDATA are blocked by the kernel on Android 15+ for
// certain system processes (zygote64); /proc/pid/mem pread/pwrite bypasses
// that restriction while still requiring root + ptrace attachment.
static bool mem_rw(pid_t pid, long address, void* buf, size_t size, bool write) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int flags = write ? O_RDWR : O_RDONLY;
    int fd = open(path, flags);
    if (fd < 0) {
        LOGE("mem_rw: open %s failed errno=%d (%s)", path, errno, strerror(errno));
        return false;
    }
    ssize_t n = write
        ? pwrite64(fd, buf, size, (off64_t)address)
        : pread64(fd, buf, size, (off64_t)address);
    close(fd);
    if (n != (ssize_t)size) {
        LOGE("mem_rw: %s pid=%d addr=0x%lx size=%zu got=%zd errno=%d (%s)",
             write ? "pwrite" : "pread", pid, address, size, n, errno, strerror(errno));
        return false;
    }
    return true;
}

void ptrace_read(pid_t pid, long address, uint8_t* buffer, size_t size) {
    if (pid <= 0 || address == 0 || buffer == nullptr || size == 0) {
        LOGE("ptrace_read: invalid args pid=%d address=%lx size=%zu", pid, address, size);
        return;
    }
    memset(buffer, 0, size);
    mem_rw(pid, address, buffer, size, false);
}

void ptrace_write(pid_t pid, long address, void* data, size_t size) {
    if (pid <= 0 || address == 0 || data == nullptr || size == 0) {
        LOGE("ptrace_write: invalid args pid=%d address=%lx size=%zu", pid, address, size);
        return;
    }
    mem_rw(pid, address, data, size, true);
}
