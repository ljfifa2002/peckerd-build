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

#define NINJECTOR_RESULT_FILE "/data/local/tmp/ninjector_result.json"
#define NINJECTOR_LOCK_PREFIX "/data/local/tmp/ncore_injected_"

// Build lock-file path for a package name.
// Returns length written (not including null), or 0 on overflow.
static size_t lock_path(char* buf, size_t buf_size, const char* pkg) {
    size_t n = snprintf(buf, buf_size, "%s%s", NINJECTOR_LOCK_PREFIX, pkg);
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
    if (fd >= 0) close(fd);
}

// Remove the injection lock file for a package (called on reset/clear).
static void clear_injected(const char* pkg) {
    if (!pkg) return;
    char path[256];
    if (!lock_path(path, sizeof(path), pkg)) return;
    unlink(path);
}

static char* g_target_package = nullptr;
static char* g_target_so = nullptr;
static void* g_android_os_Process_setArg = nullptr;
static void* g_selinux_android_setcontext = nullptr;
static bool g_payload_loaded = false;
static bool g_spawn_hooks_installed = false;

static void send_status_to_injector(const char* package_name, const char* so_path) {
    char payload[512] = {0};
    snprintf(payload,
             sizeof(payload),
             "{\"pid\":%d,\"pkg\":\"%s\",\"so\":\"%s\"}",
             getpid(),
             package_name != nullptr ? package_name : "",
             so_path != nullptr ? so_path : "");

    int fd = open(NINJECTOR_RESULT_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd < 0) {
        LOGE("ncore: open result file failed");
        return;
    }

    ssize_t written = write(fd, payload, strlen(payload));
    if (written < 0) {
        LOGE("ncore: write result file failed");
        close(fd);
        return;
    }

    LOGI("ncore: sent callback payload=%s", payload);
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
    // Do NOT clear the injection lock here — the lock must persist across
    // multiple ainject() calls for the same package so that subsequent forked
    // processes skip injection. Lock is only removed by aclear() or when
    // ainject() switches to a different target package.
    if (g_target_package != nullptr) {
        free(g_target_package);
        g_target_package = nullptr;
    }
    if (g_target_so != nullptr) {
        free(g_target_so);
        g_target_so = nullptr;
    }
    g_payload_loaded = false;
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
    unhook_all();
    if (g_target_package != nullptr) {
        clear_injected(g_target_package);
    }
    unload_target_state();
}

static void preload_deps(const char* so_path) {
    const char* last_slash = strrchr(so_path, '/');
    if (last_slash == nullptr) return;
    size_t dir_len = (size_t)(last_slash - so_path + 1);

    const char* deps[] = {"liblsplant.so", "libshadowhook.so", nullptr};
    for (int i = 0; deps[i] != nullptr; i++) {
        char dep_path[512] = {0};
        snprintf(dep_path, sizeof(dep_path), "%.*s%s", (int)dir_len, so_path, deps[i]);
        void* h = dlopen(dep_path, RTLD_NOW | RTLD_GLOBAL);
        if (h == nullptr) {
            LOGD("ncore: preload %s skipped: %s", dep_path, dlerror());
        } else {
            LOGI("ncore: preloaded %s", dep_path);
        }
    }
}

static bool load_payload_if_needed(const char* package_name) {
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

    void* handle = dlopen(g_target_so, RTLD_NOW | RTLD_NODELETE | RTLD_GLOBAL);
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
    pid_t pid = orig_fork();
    if (pid == 0) {
        LOGI("ncore: child forked pid=%d", getpid());
        install_child_hooks();
    } else if (pid > 0) {
        LOGD("ncore: parent observed fork child=%d", pid);
    }
    return pid;
}

DECLARE_HOOK(vfork, pid_t, void) {
    LOGD("ncore: vfork called");
    return fake_fork();
}

extern "C" void ainject(const char* package_name, const char* so_path) {
    // If switching to a different target package, clear the old package's lock.
    if (g_target_package != nullptr && package_name != nullptr &&
        strcmp(g_target_package, package_name) != 0) {
        clear_injected(g_target_package);
    }

    unload_target_state();

    if (package_name != nullptr && package_name[0] != '\0') {
        g_target_package = strdup(package_name);
    }
    if (so_path != nullptr && so_path[0] != '\0') {
        g_target_so = strdup(so_path);
    }

    LOGI("ncore: ainject package=%s so=%s",
         g_target_package != nullptr ? g_target_package : "(null)",
         g_target_so != nullptr ? g_target_so : "(null)");

    if (g_spawn_hooks_installed) {
        LOGI("ncore: spawn hooks already installed, skip");
        return;
    }

    INSTALL_HOOK(fork, fork);
    INSTALL_HOOK(vfork, vfork);
    g_spawn_hooks_installed = true;
    LOGI("ncore: spawn hooks installed");
}

__attribute__((destructor()))
static void ncore_cleanup() {
    LOGD("ncore: cleanup");
    unhook_all();
    if (g_target_package != nullptr) {
        clear_injected(g_target_package);
    }
    unload_target_state();
}
