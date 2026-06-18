#include "ncore.h"
#include "simple_hook.h"
#include "../common/log.h"

#include <jni.h>
#include <unistd.h>
#include <dlfcn.h>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <cerrno>

// memfd_create is not declared in older NDK headers; call via syscall directly.
static int ncore_memfd_create(const char* name, unsigned int flags) {
    return (int)syscall(__NR_memfd_create, name, flags);
}

// ---------------------------------------------------------------------------
// memfd_load: load a .so from disk via an anonymous memfd so the real file
// path never appears in /proc/self/maps.  The mapping shows as
// "memfd:<name> (deleted)" instead of the original path.
// Returns dlopen handle or nullptr on failure.
// ---------------------------------------------------------------------------
static void* memfd_load(const char* path, int dlopen_flags) {
    int src = open(path, O_RDONLY);
    if (src < 0) {
        LOGE("ncore: memfd_load open(%s) errno=%d", path, errno);
        return nullptr;
    }

    struct stat st;
    if (fstat(src, &st) < 0) { close(src); return nullptr; }
    size_t size = (size_t)st.st_size;

    // Use a neutral name — anything without the real library name.
    int mfd = ncore_memfd_create("lib", MFD_CLOEXEC);
    if (mfd < 0) {
        LOGE("ncore: memfd_create errno=%d", errno);
        close(src);
        return nullptr;
    }

    if (ftruncate(mfd, (off_t)size) < 0) { close(mfd); close(src); return nullptr; }

    // mmap source file and write to memfd
    void* mapped = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, src, 0);
    close(src);
    if (mapped == MAP_FAILED) { close(mfd); return nullptr; }

    ssize_t written = write(mfd, mapped, size);
    munmap(mapped, size);
    if (written != (ssize_t)size) { close(mfd); return nullptr; }

    // dlopen via /proc/self/fd/<n>
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", mfd);
    void* handle = dlopen(fd_path, dlopen_flags);
    close(mfd);   // handle keeps the mapping alive; fd itself can be closed

    if (!handle) LOGE("ncore: memfd dlopen(%s) failed: %s", path, dlerror());
    else          LOGI("ncore: memfd loaded %s", path);
    return handle;
}

#if defined(__aarch64__)
#define PECKERD_RESULT_DIR "/data/local/tmp/pecker64"
#else
#define PECKERD_RESULT_DIR "/data/local/tmp/pecker32"
#endif
// Two fixed result files — one per task type.  Named by task type rather than
// package name so the device never accumulates per-package files.
// Determined by target package prefix: com.tencent.mm → applet, else → APK.
#define PECKERD_RESULT_APK       PECKERD_RESULT_DIR "/peckerd_apk_result.json"
#define PECKERD_RESULT_APPLET_WX PECKERD_RESULT_DIR "/peckerd_applet_wx_result.json"

static const char* result_file_for_pkg(const char* pkg) {
    if (pkg != nullptr && strncmp(pkg, "com.tencent.mm", 14) == 0) {
        return PECKERD_RESULT_APPLET_WX;
    }
    return PECKERD_RESULT_APK;
}

// v2 prefix removed: the detection device always runs the latest ncore build,
// so version-based lock-file conflicts cannot occur in practice.
// The plain prefix is kept consistent with historical lock files on device.
#define PECKERD_LOCK_PREFIX "/data/local/tmp/ncore_injected_"
// Per-zygote-PID file that marks fork/vfork hooks as installed.
// Keyed by PID so a zygote restart (new PID) gets a clean slate.
// Guards against double-hooking when multiple ncore SO instances are loaded
// via memfd (each memfd gets a unique inode, making the linker treat them as
// separate libraries with independent globals and Dobby state).
#define PECKERD_HOOKS_PREFIX "/data/local/tmp/ncore_hooks_"
// Shared target file: ainject writes package+so, install_child_hooks reads it
// so that fork hooks from stale ncore instances still pick up the current target.
#define NCORE_TARGET_FILE PECKERD_RESULT_DIR "/ncore_target"
// aclear address file: written when this instance installs fork hooks so that
// clear_spawn_in_zygote can find aclear on 32-bit Android 11 where RTLD_DEFAULT
// does not expose memfd-loaded SO symbols.
#define NCORE_ACLEAR_ADDR_FILE PECKERD_RESULT_DIR "/ncore_aclear_addr"

// Build lock-file path for a package name.
// Returns length written (not including null), or 0 on overflow.
static size_t lock_path(char* buf, size_t buf_size, const char* pkg) {
    size_t n = snprintf(buf, buf_size, "%s%s", PECKERD_LOCK_PREFIX, pkg);
    return (n < buf_size) ? n : 0;
}

// Returns true if this package has already been injected in another process.
static bool is_already_injected(const char* pkg) {
    char path[256];
    if (!lock_path(path, sizeof(path), pkg)) return false;
    struct stat st;
    return stat(path, &st) == 0;
}

// Mark this package as injected (creates the lock file).
static void mark_injected(const char* pkg) {
    char path[256];
    if (!lock_path(path, sizeof(path), pkg)) return;
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd >= 0) {
        close(fd);
        LOGI("ncore: injection lock created: %s", path);
    } else {
        LOGE("ncore: injection lock create FAILED: %s errno=%d", path, errno);
    }
}

// Remove the injection lock file for a package (called on reset/clear).
static void clear_injected(const char* pkg) {
    if (!pkg) return;
    char path[256];
    if (!lock_path(path, sizeof(path), pkg)) return;
    unlink(path);
}

// Cross-instance hook-state helpers.
// Use getpid() (= zygote PID) so a zygote restart automatically invalidates
// the previous state without any explicit cleanup.
static void hooks_state_path(char* buf, size_t buf_size) {
    snprintf(buf, buf_size, "%s%d", PECKERD_HOOKS_PREFIX, getpid());
}

static bool hooks_state_active() {
    char path[64];
    hooks_state_path(path, sizeof(path));
    struct stat st;
    return stat(path, &st) == 0;
}

static void hooks_state_set(bool active) {
    char path[64];
    hooks_state_path(path, sizeof(path));
    if (active) {
        int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
        if (fd >= 0) close(fd);
    } else {
        unlink(path);
    }
}

static char* g_target_package = nullptr;
static char* g_target_so = nullptr;
static void* g_android_os_Process_setArg = nullptr;
static void* g_selinux_android_setcontext = nullptr;
static bool g_payload_loaded = false;
static bool g_spawn_hooks_installed = false;
// Set to true by the parent fork hook after the first injection target has been
// dispatched. Inherited by subsequent children via fork copy-on-write, causing
// them to skip hook installation entirely.  Reset only by aclear()/ainject().
static bool g_injection_done = false;

// Forward declaration: aclear is defined later; needed by write_aclear_addr_file.
extern "C" void aclear();

// Write the virtual address of aclear() in this process to NCORE_ACLEAR_ADDR_FILE.
// Called only when this ncore instance actually installs the fork hooks, so the
// address always belongs to the instance that owns the live hooks.
// clear_spawn_in_zygote reads this file as a fallback when dlsym(RTLD_DEFAULT)
// cannot find aclear (e.g. 32-bit Android 11 with memfd-loaded SO).
static void write_aclear_addr_file() {
    int fd = open(NCORE_ACLEAR_ADDR_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd < 0) {
        LOGE("ncore: write_aclear_addr_file open failed errno=%d", errno);
        return;
    }
    dprintf(fd, "%lx\n", (unsigned long)(uintptr_t)aclear);
    close(fd);
    LOGD("ncore: aclear addr written %lx", (unsigned long)(uintptr_t)aclear);
}

// Write current target (package + so_path) to NCORE_TARGET_FILE so that
// fork hooks from any ncore instance (including stale ones) can read the
// authoritative target at child-init time.
static void write_target_file() {
    if (g_target_package == nullptr || g_target_so == nullptr) return;
    int fd = open(NCORE_TARGET_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd < 0) {
        LOGE("ncore: write_target_file open failed errno=%d", errno);
        return;
    }
    // Format: "<package>\n<so_path>\n"
    dprintf(fd, "%s\n%s\n", g_target_package, g_target_so);
    close(fd);
    LOGD("ncore: target file written pkg=%s", g_target_package);
}

// Read target file and update g_target_package / g_target_so if the file
// contains different (newer) values.  Called at the top of install_child_hooks
// so that even a stale ncore instance picks up the target set by ainject on
// the current (newer) instance.
static void sync_target_from_file() {
    int fd = open(NCORE_TARGET_FILE, O_RDONLY);
    if (fd < 0) return;  // file absent — keep existing globals

    char buf[512] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;

    // Parse "<package>\n<so_path>\n"
    char* nl = strchr(buf, '\n');
    if (nl == nullptr) return;
    *nl = '\0';
    const char* pkg = buf;
    const char* so  = nl + 1;
    char* nl2 = strchr(const_cast<char*>(so), '\n');
    if (nl2 != nullptr) *nl2 = '\0';

    if (pkg[0] == '\0' || so[0] == '\0') return;

    // Only update if different from current globals to avoid redundant strdup.
    bool pkg_changed = (g_target_package == nullptr || strcmp(g_target_package, pkg) != 0);
    bool so_changed  = (g_target_so      == nullptr || strcmp(g_target_so,      so)  != 0);
    if (pkg_changed) {
        if (g_target_package != nullptr) free(g_target_package);
        g_target_package = strdup(pkg);
        LOGI("ncore: sync_target_from_file pkg=%s", g_target_package);
    }
    if (so_changed) {
        if (g_target_so != nullptr) free(g_target_so);
        g_target_so = strdup(so);
        LOGI("ncore: sync_target_from_file so=%s", g_target_so);
    }
}

static void send_status_to_injector(const char* package_name, const char* so_path) {
    // Select result file by task type (not package name) so the device never
    // accumulates per-package files.  Use g_target_package so that sub-processes
    // like com.tencent.mm:appbrand0 still write to the applet file.
    const char* target = (g_target_package != nullptr) ? g_target_package
                                                        : package_name;
    const char* result_path = result_file_for_pkg(target);

    char payload_buf[512] = {0};
    snprintf(payload_buf,
             sizeof(payload_buf),
             "{\"pid\":%d,\"pkg\":\"%s\",\"so\":\"%s\"}",
             getpid(),
             package_name != nullptr ? package_name : "",
             so_path != nullptr ? so_path : "");

    // unlink before open: directory write permission lets us remove a file
    // owned by a different app uid from a previous task, avoiding EACCES on
    // the subsequent O_CREAT|O_WRONLY open.
    unlink(result_path);

    int fd = open(result_path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd < 0) {
        LOGE("ncore: open result file failed path=%s errno=%d", result_path, errno);
        return;
    }

    ssize_t written = write(fd, payload_buf, strlen(payload_buf));
    if (written < 0) {
        LOGE("ncore: write result file failed path=%s errno=%d", result_path, errno);
        close(fd);
        return;
    }

    LOGI("ncore: sent callback payload=%s path=%s", payload_buf, result_path);
    close(fd);
}

static bool matches_target(const char* name) {
    if (g_target_package == nullptr || g_target_so == nullptr || name == nullptr) {
        return false;
    }
    size_t pkg_len = strlen(g_target_package);
    // Match exact name or sub-process with ":<suffix>" (e.g. ":channel")
    bool matched = strncmp(name, g_target_package, pkg_len) == 0 &&
                   (name[pkg_len] == '\0' || name[pkg_len] == ':');
    if (name != nullptr) {
        LOGD("ncore: compare target current=%s target=%s matched=%d",
             name,
             g_target_package != nullptr ? g_target_package : "(null)",
             matched ? 1 : 0);
    }
    return matched;
}

static void unload_target_state() {
    if (g_target_package != nullptr) {
        free(g_target_package);
        g_target_package = nullptr;
    }
    if (g_target_so != nullptr) {
        free(g_target_so);
        g_target_so = nullptr;
    }
    g_payload_loaded = false;
    g_injection_done = false;
}

static void unhook_all() {
    DobbyDestroy(reinterpret_cast<void*>(fork));
    DobbyDestroy(reinterpret_cast<void*>(vfork));
    if (g_android_os_Process_setArg != nullptr) {
        DobbyDestroy(g_android_os_Process_setArg);
        g_android_os_Process_setArg = nullptr;
    }
    if (g_selinux_android_setcontext != nullptr) {
        DobbyDestroy(g_selinux_android_setcontext);
        g_selinux_android_setcontext = nullptr;
    }
    g_spawn_hooks_installed = false;
}

extern "C" void aclear() {
    LOGI("ncore: aclear");
    // Remove state file BEFORE unhooking so a concurrent ainject() in another
    // ncore instance sees no active hooks and can safely re-install them after
    // this unhook completes.
    hooks_state_set(false);
    unhook_all();
    if (g_target_package != nullptr) {
        clear_injected(g_target_package);
    }
    unload_target_state();
    unlink(NCORE_TARGET_FILE);
    unlink(NCORE_ACLEAR_ADDR_FILE);
}

static void preload_deps(const char* so_path) {
    const char* last_slash = strrchr(so_path, '/');
    if (last_slash == nullptr) return;
    size_t dir_len = (size_t)(last_slash - so_path + 1);

    const char* deps[] = {"liblsplant.so", "libshadowhook.so", nullptr};
    for (int i = 0; deps[i] != nullptr; i++) {
        char dep_path[512] = {0};
        snprintf(dep_path, sizeof(dep_path), "%.*s%s", (int)dir_len, so_path, deps[i]);
        void* h = memfd_load(dep_path, RTLD_NOW | RTLD_GLOBAL);
        if (h == nullptr) {
            LOGD("ncore: preload %s skipped", dep_path);
        } else {
            LOGI("ncore: preloaded %s", dep_path);
        }
    }
}

static bool load_payload_if_needed(const char* package_name) {
    // Re-read the authoritative target at specialization time, not just at fork
    // time. sync_target_from_file() also runs in install_child_hooks(), but a
    // pre-forked blank (ColorOS USAP slot) is forked under whatever target was
    // current then, and may only be specialized into an app many seconds later
    // under a newer task's target. Without refreshing here, such a blank compares
    // against a stale g_target_package, never matches the app it becomes, and
    // injects nothing -> the spawn callback times out (~20s) and pecker retries.
    sync_target_from_file();

    if (!matches_target(package_name)) {
        return false;
    }

    if (g_payload_loaded) {
        LOGI("ncore: payload already loaded for %s", package_name);
        return true;
    }

    // Cross-process one-shot guard: if another forked process already loaded
    // the payload for this package, skip injection in this process.
    // This prevents an infinite fork loop when the app uses multi-process
    // watchdog/guardian patterns (all children share the same package name).
    if (is_already_injected(g_target_package)) {
        LOGI("ncore: payload already injected in another process for %s, skipping",
             package_name);
        return true;
    }

    LOGI("ncore: target matched, loading payload package=%s so=%s",
         package_name != nullptr ? package_name : "(null)",
         g_target_so != nullptr ? g_target_so : "(null)");

    unhook_all();
    preload_deps(g_target_so);

    // Expose the exact process name to payload_init() via an env variable so it
    // can filter by sub-process name (:appbrand, :push, etc.) at constructor time.
    // /proc/self/cmdline is not yet updated when the constructor runs (that only
    // happens later via android_os_Process_setArgV0), so this is the only
    // reliable way to pass the name without modifying the payload's ABI.
    if (package_name != nullptr) {
        setenv("NCORE_PROCESS_NAME", package_name, 1);
    }

    void* handle = memfd_load(g_target_so, RTLD_NOW | RTLD_NODELETE | RTLD_GLOBAL);
    if (handle == nullptr) {
        LOGE("ncore: dlopen failed for %s: %s", g_target_so, dlerror());
        return false;
    }

    g_payload_loaded = true;
    mark_injected(g_target_package);
    LOGI("ncore: payload loaded for %s => %s", package_name, g_target_so);
    send_status_to_injector(package_name, g_target_so);
    return true;
}

DECLARE_HOOK(selinux_android_setcontext, int, uid_t uid, bool isSystemServer, const char* seinfo, const char* name) {
    int result = orig_selinux_android_setcontext(uid, isSystemServer, seinfo, name);
    LOGD("ncore: selinux_android_setcontext name=%s", name != nullptr ? name : "(null)");
    load_payload_if_needed(name);
    return result;
}

DECLARE_HOOK(android_os_Process_setArgV0, void, JNIEnv* env, jobject obj, jstring arg) {
    const char* package_name = env != nullptr && arg != nullptr ? env->GetStringUTFChars(arg, nullptr) : nullptr;
    if (orig_android_os_Process_setArgV0 != nullptr) {
        orig_android_os_Process_setArgV0(env, obj, arg);
    }

    LOGD("ncore: android_os_Process_setArgV0 arg=%s", package_name != nullptr ? package_name : "(null)");
    load_payload_if_needed(package_name);

    if (env != nullptr && arg != nullptr && package_name != nullptr) {
        env->ReleaseStringUTFChars(arg, package_name);
    }
}

static void install_child_hooks() {
    // Refresh target from the shared file so that even a stale ncore instance
    // (whose g_target_package was set by a previous task) uses the current target.
    sync_target_from_file();
    LOGI("ncore: installing child hooks pid=%d", getpid());

    g_android_os_Process_setArg = DobbySymbolResolver(
        "libandroid_runtime.so",
        "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring");
    if (g_android_os_Process_setArg != nullptr) {
        INSTALL_HOOK(android_os_Process_setArgV0, g_android_os_Process_setArg);
    } else {
        LOGE("ncore: android_os_Process_setArgV0 not found");
    }

    g_selinux_android_setcontext = DobbySymbolResolver("libselinux.so", "selinux_android_setcontext");
    if (g_selinux_android_setcontext != nullptr) {
        INSTALL_HOOK(selinux_android_setcontext, g_selinux_android_setcontext);
    } else {
        LOGE("ncore: selinux_android_setcontext not found");
    }
}

DECLARE_HOOK(fork, pid_t, void) {
    // Snapshot the flag before forking so the child inherits a consistent value.
    bool already_done = g_injection_done;
    pid_t pid = orig_fork();
    if (pid == 0) {
        // Child process
        if (already_done) {
            // Parent confirmed target already injected; skip hooks in this child.
            LOGI("ncore: child forked pid=%d, injection already done, skipping hooks",
                 getpid());
        } else if (g_target_package != nullptr && is_already_injected(g_target_package)) {
            // Lock file exists: target loaded payload in a concurrent sibling.
            // Skip hook installation to avoid redundant work.
            LOGI("ncore: child forked pid=%d, target already injected via lock, skipping hooks",
                 getpid());
        } else {
            LOGI("ncore: child forked pid=%d", getpid());
            install_child_hooks();
        }
    } else if (pid > 0) {
        LOGD("ncore: parent observed fork child=%d", pid);
        // Only mark injection done once the target package has confirmed it loaded
        // payload (lock file created by mark_injected in the child). This prevents
        // pre-marking done when an unrelated process (e.g. a content provider) is
        // forked before the actual target app, which would cause the target fork to
        // inherit already_done=true and skip hook installation entirely.
        if (!already_done && g_target_package != nullptr && is_already_injected(g_target_package)) {
            g_injection_done = true;
            LOGI("ncore: marked injection done, target confirmed: %s", g_target_package);
        }
    }
    return pid;
}

DECLARE_HOOK(vfork, pid_t, void) {
    LOGD("ncore: vfork called");
    return fake_fork();
}

extern "C" void ainject(const char* package_name, const char* so_path) {
    // Always reset injection state when a new task starts: clear the per-package
    // lock file and reset g_injection_done so the next fork triggers a fresh
    // payload load. The same_package check that preserved g_injection_done was
    // removed because each external peckerd invocation is a new task and needs
    // a clean slate regardless of whether the package name changed.
    if (g_target_package != nullptr) {
        clear_injected(g_target_package);
    }
    unload_target_state();  // resets g_injection_done, g_payload_loaded

    if (g_target_package != nullptr) { free(g_target_package); g_target_package = nullptr; }
    if (g_target_so     != nullptr) { free(g_target_so);      g_target_so      = nullptr; }
    if (package_name != nullptr && package_name[0] != '\0') {
        g_target_package = strdup(package_name);
    }
    if (so_path != nullptr && so_path[0] != '\0') {
        g_target_so = strdup(so_path);
    }

    LOGI("ncore: ainject package=%s so=%s",
         g_target_package != nullptr ? g_target_package : "(null)",
         g_target_so != nullptr ? g_target_so : "(null)");

    // Persist target to disk so install_child_hooks() on any ncore instance
    // (including stale ones with old g_target_package) reads the current target.
    write_target_file();

    if (g_spawn_hooks_installed || hooks_state_active()) {
        // Hooks already installed by this or a previous ncore instance.
        // g_injection_done was reset above so the next fork will load payload fresh.
        // The target file written above ensures child processes from stale instances
        // will read the correct current target via sync_target_from_file().
        LOGI("ncore: spawn hooks already installed, reusing (injection_done reset)");
        return;
    }

    INSTALL_HOOK(fork, fork);
    INSTALL_HOOK(vfork, vfork);
    g_spawn_hooks_installed = true;
    hooks_state_set(true);
    write_aclear_addr_file();
    LOGI("ncore: spawn hooks installed");
}

__attribute__((destructor()))
static void ncore_cleanup() {
    LOGD("ncore: cleanup");
    unhook_all();
    // Do NOT clear the injection lock on process exit — the lock must outlive
    // individual worker processes so subsequent forks see it and skip injection.
    // Lock is only cleared by an explicit aclear() call.
    unload_target_state();
}
