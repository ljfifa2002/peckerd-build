#include "injector.h"
#include "../common/log.h"
#if defined(__aarch64__)
#include "../ptrace/ptrace_arm64.h"
#else
#include "../ptrace/ptrace_arm.h"
#endif

#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

// ABI-specific path for the aclear address file written by ncore when it
// installs fork hooks.  Used as a fallback when dlsym(RTLD_DEFAULT,"aclear")
// returns null (32-bit Android 11 where memfd-loaded SO symbols are not
// visible in the global namespace).
#if defined(__aarch64__)
#define NCORE_ACLEAR_ADDR_FILE "/data/local/tmp/pecker64/ncore_aclear_addr"
#else
#define NCORE_ACLEAR_ADDR_FILE "/data/local/tmp/pecker32/ncore_aclear_addr"
#endif

static void* remote_alloc_string(pid_t pid, const char* str) {
    if (pid <= 0 || str == nullptr || str[0] == '\0') {
        LOGE("remote_alloc_string: invalid args");
        return nullptr;
    }

    size_t len = strlen(str) + 1;
    void* remote_buf = call_remote_function<void*, size_t>(
        pid,
        reinterpret_cast<void*>(malloc),
        len
    );
    if (remote_buf == nullptr) {
        LOGE("remote_alloc_string: remote malloc failed");
        return nullptr;
    }

    ptrace_write(pid, reinterpret_cast<long>(remote_buf), const_cast<char*>(str), len);
    LOGD("remote_alloc_string: wrote string to remote addr=%p", remote_buf);
    return remote_buf;
}

static void* inject_so_handle_by_pid(pid_t pid, const char* so_path) {
    if (pid <= 0 || so_path == nullptr || so_path[0] == '\0') {
        LOGE("inject_so_handle_by_pid: invalid args");
        return nullptr;
    }

    // Read the SO file locally so we can push its content into the remote memfd.
    int src_fd = open(so_path, O_RDONLY);
    if (src_fd < 0) {
        LOGE("inject_so_handle_by_pid: open(%s) errno=%d", so_path, errno);
        return nullptr;
    }
    struct stat st;
    if (fstat(src_fd, &st) < 0) {
        LOGE("inject_so_handle_by_pid: fstat errno=%d", errno);
        close(src_fd);
        return nullptr;
    }
    size_t so_size = (size_t)st.st_size;
    void* so_buf = mmap(nullptr, so_size, PROT_READ, MAP_PRIVATE, src_fd, 0);
    close(src_fd);
    if (so_buf == MAP_FAILED) {
        LOGE("inject_so_handle_by_pid: local mmap errno=%d", errno);
        return nullptr;
    }

    // Remote-memfd approach: create the memfd inside zygote so dlopen uses
    // "/proc/self/fd/N" — a self-reference that has no cross-domain SELinux
    // restriction, unlike "/proc/<peckerd_pid>/fd/N" (denied on HarmonyOS 4.x
    // where zygote cannot read magisk-context process fd symlinks).
    //
    // Writing to the remote memfd differs by ABI:
    //   ARM64: ftruncate + mmap (MAP_SHARED) + ptrace_write + munmap
    //   ARM32: malloc + ptrace_write + write(fd,buf,n) + free
    // The ARM32 path avoids calling mmap remotely because mmap's 6th argument
    // (off_t offset) is 64-bit on ARM32, and the ARM32 AAPCS requires 64-bit
    // arguments on the stack to be 8-byte aligned with a padding slot before
    // them.  Our template does not insert that padding, so the call would be
    // mis-formed.  write() takes only 32-bit arguments and has no alignment
    // issue; memfd_create extends its backing store automatically on write.
    bool attached    = false;
    void* name_ptr   = nullptr;
    int   remote_mfd = -1;
    void* path_ptr   = nullptr;
    void* handle     = nullptr;
#if defined(__aarch64__)
    void* mapped_addr = reinterpret_cast<void*>(-1); // MAP_FAILED sentinel
#else
    void* remote_buf  = nullptr;
#endif

    if (!attach_process(pid)) {
        LOGE("inject_so_handle_by_pid: attach failed, pid=%d", pid);
        munmap(so_buf, so_size);
        return nullptr;
    }
    attached = true;
    LOGI("inject_so_handle_by_pid: attached to pid=%d", pid);

    // Step 1: allocate the memfd name string in the remote process.
    name_ptr = remote_alloc_string(pid, "lib");
    if (name_ptr == nullptr) {
        LOGE("inject_so_handle_by_pid: remote alloc name failed");
        goto fail;
    }

    // Step 2: remote memfd_create("lib", MFD_CLOEXEC) — creates an anonymous
    // in-memory file owned by the remote process.
    {
        void* r = call_remote_function<void*>(
            pid,
            reinterpret_cast<void*>(syscall),
            (long)__NR_memfd_create,
            (long)(uintptr_t)name_ptr,
            (long)MFD_CLOEXEC
        );
        remote_mfd = (int)(long)(uintptr_t)r;
    }
    call_remote_function<void, void*>(pid, reinterpret_cast<void*>(free), name_ptr);
    name_ptr = nullptr;

    if (remote_mfd < 0) {
        LOGE("inject_so_handle_by_pid: remote memfd_create failed ret=%d", remote_mfd);
        goto fail;
    }
    LOGI("inject_so_handle_by_pid: remote memfd_create ok fd=%d", remote_mfd);

    // Step 3: populate the remote memfd with the SO content.
#if defined(__aarch64__)
    // ARM64: size the memfd, map it shared+writable, fill via /proc/<pid>/mem,
    // then unmap (content stays in the memfd).
    call_remote_function<void*, int, off_t>(
        pid, reinterpret_cast<void*>(ftruncate), remote_mfd, (off_t)so_size);

    mapped_addr = call_remote_function<void*, void*, size_t, int, int, int, off_t>(
        pid, reinterpret_cast<void*>(mmap),
        (void*)nullptr, so_size, PROT_READ | PROT_WRITE, MAP_SHARED, remote_mfd, (off_t)0);

    if (mapped_addr == reinterpret_cast<void*>(-1) || mapped_addr == nullptr) {
        LOGE("inject_so_handle_by_pid: remote mmap failed");
        goto fail;
    }
    LOGI("inject_so_handle_by_pid: remote mmap at %p size=%zu", mapped_addr, so_size);

    ptrace_write(pid, reinterpret_cast<long>(mapped_addr), so_buf, so_size);
    munmap(so_buf, so_size);
    so_buf = MAP_FAILED;

    call_remote_function<void*, void*, size_t>(
        pid, reinterpret_cast<void*>(munmap), mapped_addr, so_size);
    mapped_addr = reinterpret_cast<void*>(-1);
#else
    // ARM32: allocate a temp buffer in the remote process, fill it via
    // /proc/<pid>/mem, then write() it into the memfd.  write() takes only
    // 32-bit arguments (int fd, void* buf, size_t n) so there is no 64-bit
    // alignment issue, unlike mmap's 6th arg (off_t).  memfd_create returns
    // a zero-length file; write() extends it automatically.
    remote_buf = call_remote_function<void*, size_t>(
        pid, reinterpret_cast<void*>(malloc), so_size);
    if (remote_buf == nullptr) {
        LOGE("inject_so_handle_by_pid: remote malloc failed for size=%zu", so_size);
        goto fail;
    }

    ptrace_write(pid, reinterpret_cast<long>(remote_buf), so_buf, so_size);
    munmap(so_buf, so_size);
    so_buf = MAP_FAILED;

    call_remote_function<void*, int, void*, size_t>(
        pid, reinterpret_cast<void*>(write), remote_mfd, remote_buf, so_size);

    call_remote_function<void, void*>(pid, reinterpret_cast<void*>(free), remote_buf);
    remote_buf = nullptr;
#endif // __aarch64__

    // Step 4: dlopen("/proc/self/fd/<remote_mfd>") inside the remote process.
    // The remote process accesses its own fd — no cross-domain SELinux check.
    {
        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", remote_mfd);
        path_ptr = remote_alloc_string(pid, fd_path);
        if (path_ptr == nullptr) {
            LOGE("inject_so_handle_by_pid: remote alloc fd_path failed");
            goto fail;
        }
    }

    handle = call_remote_function<void*, const char*, int>(
        pid,
        reinterpret_cast<void*>(dlopen),
        reinterpret_cast<const char*>(path_ptr),
        RTLD_NOW | RTLD_GLOBAL
    );
    if (handle == nullptr) {
        LOGE("inject_so_handle_by_pid: remote dlopen failed");
        char* remote_error = call_remote_function<char*>(
            pid, reinterpret_cast<void*>(dlerror));
        if (remote_error != nullptr) {
            char error_buf[512] = {0};
            ptrace_read(pid, reinterpret_cast<long>(remote_error),
                        reinterpret_cast<uint8_t*>(error_buf), sizeof(error_buf) - 1);
            LOGE("inject_so_handle_by_pid: dlerror=%s", error_buf);
        }
        goto fail;
    }
    LOGI("inject_so_handle_by_pid: remote dlopen success handle=%p", handle);

    call_remote_function<void, void*>(pid, reinterpret_cast<void*>(free), path_ptr);
    path_ptr = nullptr;

    // Close the remote fd; dlopen keeps the mapping alive via the handle.
    call_remote_function<void*, int>(pid, reinterpret_cast<void*>(close), remote_mfd);
    remote_mfd = -1;

    if (!detach_process(pid)) {
        LOGE("inject_so_handle_by_pid: detach failed after success");
        return nullptr;
    }
    LOGI("inject_so_handle_by_pid: inject success");
    return handle;

fail:
    if (so_buf != MAP_FAILED) munmap(so_buf, so_size);
#if defined(__aarch64__)
    if (mapped_addr != reinterpret_cast<void*>(-1) && mapped_addr != nullptr) {
        call_remote_function<void*, void*, size_t>(
            pid, reinterpret_cast<void*>(munmap), mapped_addr, so_size);
    }
#else
    if (remote_buf != nullptr)
        call_remote_function<void, void*>(pid, reinterpret_cast<void*>(free), remote_buf);
#endif
    if (name_ptr != nullptr)
        call_remote_function<void, void*>(pid, reinterpret_cast<void*>(free), name_ptr);
    if (path_ptr != nullptr)
        call_remote_function<void, void*>(pid, reinterpret_cast<void*>(free), path_ptr);
    if (remote_mfd >= 0)
        call_remote_function<void*, int>(pid, reinterpret_cast<void*>(close), remote_mfd);
    if (attached) detach_process(pid);
    return nullptr;
}

bool inject_so_by_pid(pid_t pid, const char* so_path) {
    return inject_so_handle_by_pid(pid, so_path) != nullptr;
}

bool prepare_spawn_in_zygote(pid_t zygote_pid,
                             const char* ncore_path,
                             const char* package_name,
                             const char* so_path) {
    if (zygote_pid <= 0 ||
        ncore_path == nullptr || ncore_path[0] == '\0' ||
        package_name == nullptr || package_name[0] == '\0' ||
        so_path == nullptr || so_path[0] == '\0') {
        LOGE("prepare_spawn_in_zygote: invalid args");
        return false;
    }

    bool attached = false;
    void* handle = nullptr;
    void* remote_sym_name = nullptr;
    void* remote_pkg = nullptr;
    void* remote_so = nullptr;
    void* remote_ainject = nullptr;
    long params[2] = {0, 0};

    // ── Option-2: reuse existing ncore if already loaded ──────────────────────
    // Probe zygote for an already-loaded ncore instance before injecting a new SO.
    // If `ainject` is present in the global namespace (RTLD_DEFAULT), ncore was
    // previously loaded and its fork/vfork hooks are still installed.  Re-using
    // the existing instance avoids:
    //   1. Accumulating memfd SO mappings in zygote's address space.
    //   2. Repeated DobbyHook/DobbyDestroy cycles that corrupt zygote's code pages.
    //
    // Flow:
    //   a) Attach → probe RTLD_DEFAULT for "ainject".
    //   b) Found  → call ainject on the existing instance; skip SO injection.
    //   c) Missing → detach, inject new libncore.so, re-attach, call ainject.
    // ──────────────────────────────────────────────────────────────────────────
    if (!attach_process(zygote_pid)) {
        LOGE("prepare_spawn_in_zygote: attach zygote failed");
        return false;
    }
    attached = true;

    remote_sym_name = remote_alloc_string(zygote_pid, "ainject");
    if (remote_sym_name != nullptr) {
        remote_ainject = call_remote_function<void*, void*, const char*>(
            zygote_pid,
            reinterpret_cast<void*>(dlsym),
            static_cast<void*>(nullptr),  // RTLD_DEFAULT
            reinterpret_cast<const char*>(remote_sym_name)
        );
    }

    if (remote_ainject != nullptr) {
        // Existing ncore found — reuse it.
        LOGI("prepare_spawn_in_zygote: ncore already in zygote, reusing instance");
    } else {
        // ncore not yet in zygote — inject a fresh SO.
        if (remote_sym_name != nullptr) {
            call_remote_function<void, void*>(zygote_pid,
                reinterpret_cast<void*>(free), remote_sym_name);
            remote_sym_name = nullptr;
        }
        if (!detach_process(zygote_pid)) {
            LOGE("prepare_spawn_in_zygote: detach before inject failed");
            return false;
        }
        attached = false;

        handle = inject_so_handle_by_pid(zygote_pid, ncore_path);
        if (handle == nullptr) {
            LOGE("prepare_spawn_in_zygote: inject ncore failed");
            return false;
        }

        if (!attach_process(zygote_pid)) {
            LOGE("prepare_spawn_in_zygote: re-attach after inject failed");
            return false;
        }
        attached = true;

        remote_sym_name = remote_alloc_string(zygote_pid, "ainject");
        if (remote_sym_name == nullptr) {
            LOGE("prepare_spawn_in_zygote: alloc ainject name failed");
            goto fail;
        }
        // Prefer existing instance (RTLD_DEFAULT); fall back to freshly-loaded handle.
        remote_ainject = call_remote_function<void*, void*, const char*>(
            zygote_pid,
            reinterpret_cast<void*>(dlsym),
            static_cast<void*>(nullptr),
            reinterpret_cast<const char*>(remote_sym_name)
        );
        if (remote_ainject == nullptr) {
            remote_ainject = call_remote_function<void*, void*, const char*>(
                zygote_pid,
                reinterpret_cast<void*>(dlsym),
                handle,
                reinterpret_cast<const char*>(remote_sym_name)
            );
        }
        if (remote_ainject == nullptr) {
            LOGE("prepare_spawn_in_zygote: dlsym(ainject) failed after fresh inject");
            goto fail;
        }
    }

    remote_pkg = remote_alloc_string(zygote_pid, package_name);
    remote_so = remote_alloc_string(zygote_pid, so_path);
    if (remote_pkg == nullptr || remote_so == nullptr) {
        LOGE("prepare_spawn_in_zygote: remote string allocation failed");
        goto fail;
    }

    params[0] = reinterpret_cast<long>(remote_pkg);
    params[1] = reinterpret_cast<long>(remote_so);
    call_remote_call<void>(zygote_pid, reinterpret_cast<long>(remote_ainject), 2, params);

    call_remote_function<void, void*>(
        zygote_pid,
        reinterpret_cast<void*>(free),
        remote_sym_name
    );
    call_remote_function<void, void*>(
        zygote_pid,
        reinterpret_cast<void*>(free),
        remote_pkg
    );
    call_remote_function<void, void*>(
        zygote_pid,
        reinterpret_cast<void*>(free),
        remote_so
    );

    if (!detach_process(zygote_pid)) {
        LOGE("prepare_spawn_in_zygote: detach failed");
        return false;
    }

    LOGI("prepare_spawn_in_zygote: ncore prepared in zygote pid=%d", zygote_pid);
    return true;

fail:
    if (remote_sym_name != nullptr) {
        call_remote_function<void, void*>(
            zygote_pid,
            reinterpret_cast<void*>(free),
            remote_sym_name
        );
    }
    if (remote_pkg != nullptr) {
        call_remote_function<void, void*>(
            zygote_pid,
            reinterpret_cast<void*>(free),
            remote_pkg
        );
    }
    if (remote_so != nullptr) {
        call_remote_function<void, void*>(
            zygote_pid,
            reinterpret_cast<void*>(free),
            remote_so
        );
    }
    if (attached) {
        detach_process(zygote_pid);
    }
    return false;
}

bool clear_spawn_in_zygote(pid_t zygote_pid, const char* ncore_path) {
    if (zygote_pid <= 0) {
        LOGE("clear_spawn_in_zygote: invalid args");
        return false;
    }
    (void)ncore_path; // unused: we find aclear via RTLD_DEFAULT, not a new load

    // Do NOT load a new ncore instance here. Each load via memfd creates a
    // separate library instance with independent Dobby state and globals.
    // Calling aclear() on a fresh instance leaves the real hooks (installed by
    // the first instance) in place and causes double-hooking on the next inject.
    //
    // Instead, find aclear() in the already-loaded ncore via RTLD_DEFAULT.
    // ncore was loaded with RTLD_GLOBAL, so its symbols are in the global namespace.

    bool attached = false;
    void* remote_sym_name = nullptr;
    void* remote_aclear = nullptr;

    if (!attach_process(zygote_pid)) {
        LOGE("clear_spawn_in_zygote: attach failed");
        return false;
    }
    attached = true;

    remote_sym_name = remote_alloc_string(zygote_pid, "aclear");
    if (remote_sym_name == nullptr) {
        LOGE("clear_spawn_in_zygote: alloc sym name failed");
        goto fail;
    }

    // RTLD_DEFAULT (nullptr) searches the global symbol namespace in zygote.
    remote_aclear = call_remote_function<void*, void*, const char*>(
        zygote_pid,
        reinterpret_cast<void*>(dlsym),
        static_cast<void*>(nullptr),
        reinterpret_cast<const char*>(remote_sym_name)
    );

    call_remote_function<void, void*>(
        zygote_pid,
        reinterpret_cast<void*>(free),
        remote_sym_name
    );
    remote_sym_name = nullptr;

    if (remote_aclear == nullptr) {
        // Fallback: read aclear address from file written by ncore at hook-install
        // time.  Needed on 32-bit Android 11 where memfd-loaded SO symbols are not
        // visible via RTLD_DEFAULT even with RTLD_GLOBAL.
        int afd = open(NCORE_ACLEAR_ADDR_FILE, O_RDONLY);
        if (afd >= 0) {
            char abuf[32] = {0};
            if (read(afd, abuf, sizeof(abuf) - 1) > 0) {
                unsigned long addr = strtoul(abuf, nullptr, 16);
                if (addr != 0) {
                    remote_aclear = reinterpret_cast<void*>((uintptr_t)addr);
                    LOGI("clear_spawn_in_zygote: using aclear addr from file: %p", remote_aclear);
                }
            }
            close(afd);
        }
        if (remote_aclear == nullptr) {
            // ncore not loaded yet — nothing to clear.
            LOGI("clear_spawn_in_zygote: aclear not found (ncore not loaded), nothing to clear");
            detach_process(zygote_pid);
            return true;
        }
    }

    call_remote_call<void>(zygote_pid, reinterpret_cast<long>(remote_aclear), 0, nullptr);

    if (!detach_process(zygote_pid)) {
        LOGE("clear_spawn_in_zygote: detach failed");
        return false;
    }

    LOGI("clear_spawn_in_zygote: ncore cleared in zygote pid=%d", zygote_pid);
    return true;

fail:
    if (remote_sym_name != nullptr) {
        call_remote_function<void, void*>(
            zygote_pid,
            reinterpret_cast<void*>(free),
            remote_sym_name
        );
    }
    if (attached) {
        detach_process(zygote_pid);
    }
    return false;
}
