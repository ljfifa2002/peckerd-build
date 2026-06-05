#include "ptrace_arm.h"
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

    pid_t pid  = va_arg(args, pid_t);
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

// mem_rw: read or write target process memory.
// Primary: /proc/<pid>/mem pread/pwrite — works on Android 15+ where
// PTRACE_PEEKDATA/POKEDATA are blocked by the kernel for zygote.
// Fallback: PTRACE_PEEKDATA/POKEDATA word-by-word — works on Android 11
// where /proc/<pid>/mem writes return EIO.
static bool mem_rw(pid_t pid, long address, void* buf, size_t size, bool do_write) {
    // --- primary: /proc/<pid>/mem ---
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int flags = do_write ? O_RDWR : O_RDONLY;
    int fd = open(path, flags);
    if (fd >= 0) {
        // Cast via (unsigned long) first to zero-extend the 32-bit pointer value
        // without sign-extending bit 31 into the upper 32 bits of the off64_t.
        off64_t off = (off64_t)(unsigned long)address;
        ssize_t n = do_write
            ? pwrite64(fd, buf, size, off)
            : pread64(fd, buf, size, off);
        close(fd);
        if (n == (ssize_t)size) {
            return true;
        }
        LOGD("mem_rw: /proc/mem %s pid=%d addr=0x%lx size=%zu got=%zd errno=%d, trying ptrace fallback",
             do_write ? "pwrite" : "pread", pid, address, size, n, errno);
    } else {
        LOGD("mem_rw: open %s failed errno=%d, trying ptrace fallback", path, errno);
    }

    // --- fallback: PTRACE_PEEKDATA / PTRACE_POKEDATA word-by-word ---
    uint8_t* bytes = reinterpret_cast<uint8_t*>(buf);
    size_t done = 0;
    while (done < size) {
        long aligned = (address + (long)done) & ~(sizeof(long) - 1);
        size_t off   = (size_t)((address + (long)done) - aligned);
        long word    = ptrace(PTRACE_PEEKDATA, pid, reinterpret_cast<void*>(aligned), nullptr);
        if (errno != 0) {
            LOGE("mem_rw: PTRACE_PEEKDATA pid=%d addr=0x%lx errno=%d (%s)",
                 pid, aligned, errno, strerror(errno));
            return false;
        }
        if (do_write) {
            size_t chunk = sizeof(long) - off;
            if (chunk > size - done) chunk = size - done;
            memcpy(reinterpret_cast<uint8_t*>(&word) + off, bytes + done, chunk);
            errno = 0;
            ptrace(PTRACE_POKEDATA, pid, reinterpret_cast<void*>(aligned),
                   reinterpret_cast<void*>(word));
            if (errno != 0) {
                LOGE("mem_rw: PTRACE_POKEDATA pid=%d addr=0x%lx errno=%d (%s)",
                     pid, aligned, errno, strerror(errno));
                return false;
            }
            done += chunk;
        } else {
            size_t chunk = sizeof(long) - off;
            if (chunk > size - done) chunk = size - done;
            memcpy(bytes + done, reinterpret_cast<uint8_t*>(&word) + off, chunk);
            done += chunk;
        }
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
