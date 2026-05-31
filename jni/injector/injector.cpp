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

// Load a file into a local anonymous memfd and return the fd.
// The caller should close the fd after the remote dlopen completes.
// Returns -1 on failure.
static int local_memfd_from_file(const char* path) {
    int src = open(path, O_RDONLY);
    if (src < 0) { LOGE("local_memfd: open(%s) errno=%d", path, errno); return -1; }

    struct stat st;
    if (fstat(src, &st) < 0) { close(src); return -1; }
    size_t size = (size_t)st.st_size;

    int mfd = (int)syscall(__NR_memfd_create, "lib", MFD_CLOEXEC);
    if (mfd < 0) { LOGE("local_memfd: memfd_create errno=%d", errno); close(src); return -1; }

    ftruncate(mfd, (off_t)size);
    void* mapped = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, src, 0);
    close(src);
    if (mapped == MAP_FAILED) { close(mfd); return -1; }
    write(mfd, mapped, size);
    munmap(mapped, size);
    return mfd;
}

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

    // Load the library into a local memfd so the remote dlopen sees
    // "/proc/<our_pid>/fd/<n>" which the linker resolves to "memfd:lib (deleted)".
    // This prevents the real file path from appearing in /proc/<remote>/maps.
    int mfd = local_memfd_from_file(so_path);
    char load_path[64];
    const char* dlopen_path;
    if (mfd >= 0) {
        snprintf(load_path, sizeof(load_path), "/proc/%d/fd/%d", getpid(), mfd);
        dlopen_path = load_path;
    } else {
        LOGE("inject_so_handle_by_pid: memfd failed, falling back to direct path");
        dlopen_path = so_path;
        mfd = -1;
    }

    bool attached = false;
    void* remote_path = nullptr;
    void* handle = nullptr;

    if (!attach_process(pid)) {
        LOGE("inject_so_handle_by_pid: attach failed, pid=%d", pid);
        if (mfd >= 0) close(mfd);
        return nullptr;
    }
    attached = true;
    LOGI("inject_so_handle_by_pid: attached to pid=%d", pid);

    remote_path = remote_alloc_string(pid, dlopen_path);
    if (remote_path == nullptr) {
        LOGE("inject_so_handle_by_pid: remote_alloc_string failed");
        goto fail;
    }

    handle = call_remote_function<void*, const char*, int>(
        pid,
        reinterpret_cast<void*>(dlopen),
        reinterpret_cast<const char*>(remote_path),
        RTLD_NOW | RTLD_GLOBAL
    );
    if (handle == nullptr) {
        LOGE("inject_so_handle_by_pid: remote dlopen failed");

        char* remote_error = call_remote_function<char*>(
            pid,
            reinterpret_cast<void*>(dlerror)
        );
        if (remote_error != nullptr) {
            char error_buf[512] = {0};
            ptrace_read(pid,
                        reinterpret_cast<long>(remote_error),
                        reinterpret_cast<uint8_t*>(error_buf),
                        sizeof(error_buf) - 1);
            LOGE("inject_so_handle_by_pid: dlerror=%s", error_buf);
        } else {
            LOGE("inject_so_handle_by_pid: dlerror returned null");
        }

        goto fail;
    }

    LOGI("inject_so_handle_by_pid: remote dlopen success, handle=%p", handle);

    call_remote_function<void, void*>(
        pid,
        reinterpret_cast<void*>(free),
        remote_path
    );
    remote_path = nullptr;

    if (mfd >= 0) { close(mfd); mfd = -1; }

    if (!detach_process(pid)) {
        LOGE("inject_so_handle_by_pid: detach failed after success");
        return nullptr;
    }

    LOGI("inject_so_handle_by_pid: inject success");
    return handle;

fail:
    if (remote_path != nullptr) {
        call_remote_function<void, void*>(
            pid,
            reinterpret_cast<void*>(free),
            remote_path
        );
    }
    if (mfd >= 0) close(mfd);
    if (attached) {
        detach_process(pid);
    }
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
        // ncore not loaded yet — nothing to clear.
        LOGI("clear_spawn_in_zygote: aclear not found (ncore not loaded), nothing to clear");
        detach_process(zygote_pid);
        return true;
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
