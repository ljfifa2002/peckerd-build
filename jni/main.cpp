#include "common/log.h"
#include "injector/injector.h"
#include "process/process.h"
#include "symbi/symbi_injector.h"

#include <cstdlib>
#include <cstring>
#include <future>
#include <thread>
#include <string>
#include <fstream>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

// Bumped automatically by CI when a v* tag is pushed (see .github/workflows/build.yml).
// Format: v1.0.<build_number>
#define PECKERD_VERSION "v1.0.0"

#if defined(__aarch64__)
#define PECKERD_RESULT_DIR "/data/local/tmp/pecker64"
#else
#define PECKERD_RESULT_DIR "/data/local/tmp/pecker32"
#endif
// Build result-file path into buf.  Mirrors ncore.cpp's result_file_for_pkg.
// Path is /data/data/<pkg>/peckerd_result.json — the app process owns that
// directory and can write it, while peckerd (root) can stat/read/unlink it.
// Returns false on buffer overflow.
static bool result_file_for_pkg(char* buf, size_t buf_size, const char* pkg) {
    if (pkg == nullptr || pkg[0] == '\0') return false;
    int n = snprintf(buf, buf_size, "/data/data/%s/peckerd_result.json", pkg);
    return n > 0 && (size_t)n < buf_size;
}

static void wait_for_spawn_callback(std::promise<int>& promise_obj,
                                    const std::string& package_name) {
    char result_path[256];
    if (!result_file_for_pkg(result_path, sizeof(result_path), package_name.c_str())) {
        LOGE("main: result_file_for_pkg overflow, pkg=%s", package_name.c_str());
        promise_obj.set_value(-1);
        return;
    }

    // Remove any stale result from a previous run of this task type.
    // unlink (directory-permission based) works even when the file is owned
    // by a different app uid from a previous task, unlike O_TRUNC.
    unlink(result_path);

    int callback_pid = -1;
    std::string payload;

    for (int i = 0; i < 200; ++i) {
        struct stat st{};
        if (stat(result_path, &st) == 0 && st.st_size > 0) {
            std::ifstream file(result_path);
            if (file.good()) {
                std::getline(file, payload, '\0');
            }
            break;
        }
        usleep(100000);
    }

    if (payload.empty()) {
        promise_obj.set_value(-1);
        return;
    }

    LOGI("main: spawn callback payload=%s", payload.c_str());
    const char* pid_key = "\"pid\":";
    const char* pid_pos = strstr(payload.c_str(), pid_key);
    if (pid_pos != nullptr) {
        callback_pid = atoi(pid_pos + strlen(pid_key));
    }
    // Remove the result file after reading so the next task starts clean.
    unlink(result_path);
    promise_obj.set_value(callback_pid);
}

static bool start_target_app(const char* package_name) {
    if (package_name == nullptr || package_name[0] == '\0') {
        LOGE("start_target_app: invalid package name");
        return false;
    }

    std::string force_stop_cmd = std::string("am force-stop ") + package_name;
    std::string start_cmd = std::string("am start $(cmd package resolve-activity --brief '") +
                            package_name + "'| tail -n 1)";

    LOGI("start_target_app: force-stop package=%s", package_name);
    int force_stop_ret = system(force_stop_cmd.c_str());
    LOGI("start_target_app: force-stop ret=%d", force_stop_ret);

    // Drain the USAP pool so the app cannot be specialised from a blank that was
    // pre-forked before ncore was injected (and therefore has no hooks).  Without
    // this, ColorOS serves the first launch from a stale boot-time blank that
    // escapes ncore -> spawn-callback timeout.  No-op on devices without USAP.
#if defined(__aarch64__)
    kill_usap_processes(true);
#else
    kill_usap_processes(false);
#endif

    LOGI("start_target_app: start package=%s", package_name);
    int start_ret = system(start_cmd.c_str());
    LOGI("start_target_app: start ret=%d", start_ret);

    return start_ret == 0;
}

static std::vector<pid_t> collect_spawn_source_pids() {
    const char* names[] = {
#if defined(__aarch64__)
        "zygote64"
#else
        "zygote"
#endif
    };
    std::vector<pid_t> pids;
    for (const char* name : names) {
        pid_t pid = get_pid(name);
        if (pid > 0) {
            pids.push_back(pid);
            LOGI("main: spawn-symbi candidate source name=%s pid=%d", name, pid);
        }
    }
    return pids;
}

static void show_help(const char* name) {
    printf("Usage:\n");
    printf("  %s -P <pid> <so_path>\n", name);
    printf("  %s -f -p <package> <so_path>\n", name);
    printf("  %s --spawn-symbi -p <package> <so_path>\n", name);
    printf("  %s --clear\n", name);
    printf("  %s -h\n", name);

    LOGI("Usage:");
    LOGI("  %s -P <pid> <so_path>", name);
    LOGI("  %s -f -p <package> <so_path>", name);
    LOGI("  %s --spawn-symbi -p <package> <so_path>", name);
    LOGI("  %s --clear", name);
    LOGI("  %s -h", name);
}

int main(int argc, char* argv[]) {
    LOGI("main: peckerd version=%s", PECKERD_VERSION);
    if (argc < 2) {
        show_help(argv[0]);
        return 0;
    }

    pid_t pid = -1;
    const char* so_path = nullptr;
    const char* package_name = nullptr;
    bool spawn_mode = false;
    bool spawn_symbi_mode = false;
    bool clear_mode = false;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-P") == 0 && i + 2 < argc) {
            pid = static_cast<pid_t>(atoi(argv[++i]));
            so_path = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 2 < argc) {
            package_name = argv[++i];
            so_path = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0) {
            spawn_mode = true;
        } else if (strcmp(argv[i], "--spawn-symbi") == 0) {
            spawn_symbi_mode = true;
        } else if (strcmp(argv[i], "--clear") == 0) {
            clear_mode = true;
        } else if (strcmp(argv[i], "-h") == 0) {
            show_help(argv[0]);
            return 0;
        }
    }

    if (clear_mode) {
#if defined(__aarch64__)
        std::vector<pid_t> zygote_pids = get_zygote_pids(true);
#else
        std::vector<pid_t> zygote_pids = get_zygote_pids(false);
#endif
        if (zygote_pids.empty()) {
            LOGE("main: no zygote found");
            return -1;
        }
        char cwd[PATH_MAX] = {0};
        if (getcwd(cwd, sizeof(cwd)) == nullptr) {
            LOGE("main: getcwd failed");
            return -1;
        }
        std::string ncore_path = std::string(cwd) + "/libncore.so";
        // Clear every discovered zygote (best-effort; a stale one shouldn't block the rest).
        for (pid_t zpid : zygote_pids) {
            LOGI("main: clear zygote=%d ncore=%s", zpid, ncore_path.c_str());
            if (!clear_spawn_in_zygote(zpid, ncore_path.c_str())) {
                LOGE("main: clear failed for zygote=%d", zpid);
            }
        }
        LOGI("main: clear ok");
        return 0;
    }

    if (spawn_mode && spawn_symbi_mode) {
        LOGE("main: choose only one spawn mode");
        show_help(argv[0]);
        return -1;
    }

    if (spawn_mode) {
        if (package_name == nullptr || so_path == nullptr || so_path[0] == '\0') {
            LOGE("main: invalid spawn arguments");
            show_help(argv[0]);
            return -1;
        }

#if defined(__aarch64__)
        std::vector<pid_t> zygote_pids = get_zygote_pids(true);
#else
        std::vector<pid_t> zygote_pids = get_zygote_pids(false);
#endif
        if (zygote_pids.empty()) {
            LOGE("main: no zygote found");
            return -1;
        }

        char cwd[PATH_MAX] = {0};
        if (getcwd(cwd, sizeof(cwd)) == nullptr) {
            LOGE("main: getcwd failed");
            return -1;
        }
        std::string ncore_path = std::string(cwd) + "/libncore.so";

        // Hook EVERY discovered zygote (primary zygote64 + the OPPO fast-start
        // "zygote"), so the target app is caught no matter which one forks it.
        // Without this, an app cold-started from the fast-start zygote escapes the
        // zygote64-only hook -> spawn callback timeout -> inject failure.
        int prepared = 0;
        for (pid_t zpid : zygote_pids) {
            LOGI("main: spawn mode zygote=%d package=%s so=%s ncore=%s",
                 zpid, package_name, so_path, ncore_path.c_str());
            if (prepare_spawn_in_zygote(zpid, ncore_path.c_str(), package_name, so_path)) {
                prepared++;
            } else {
                LOGE("main: spawn prepare failed for zygote=%d", zpid);
            }
        }
        if (prepared == 0) {
            LOGE("main: spawn prepare failed for all zygotes");
            return -1;
        }

        LOGI("main: spawn prepare success (%d zygote(s))", prepared);

        std::promise<int> promise_obj;
        std::future<int> future = promise_obj.get_future();
        std::thread callback_thread(wait_for_spawn_callback,
                                    std::ref(promise_obj),
                                    std::string(package_name));

        if (!start_target_app(package_name)) {
            callback_thread.join();
            LOGE("main: auto start target app failed");
            return -1;
        }

        callback_thread.join();
        int callback_pid = future.get();
        if (callback_pid > 0) {
            LOGI("main: spawn inject success child_pid=%d", callback_pid);
            // 不自动 clear：让 ncore 继续为后续匹配的子进程（主进程等）注入
            // 注入完成后手动执行 --clear
        } else {
            LOGE("main: spawn callback timeout or failed");
            return -1;
        }

        LOGI("main: auto start target app success");
        return 0;
    }

    if (spawn_symbi_mode) {
        if (package_name == nullptr || so_path == nullptr || so_path[0] == '\0') {
            LOGE("main: invalid spawn-symbi arguments");
            show_help(argv[0]);
            return -1;
        }

        std::vector<pid_t> spawn_source_pids = collect_spawn_source_pids();
        if (spawn_source_pids.empty()) {
            LOGE("main: no spawn source processes found");
            return -1;
        }

        LOGI("main: spawn-symbi mode sources=%zu package=%s so=%s",
              spawn_source_pids.size(), package_name, so_path);
        return inject_spawn_symbi_by_pids(spawn_source_pids, package_name, so_path) ? 0 : -1;
    }

    if (pid <= 0 || so_path == nullptr || so_path[0] == '\0') {
        LOGE("main: invalid arguments");
        show_help(argv[0]);
        return -1;
    }

    LOGI("main: pid=%d so=%s", pid, so_path);
    if (!inject_so_by_pid(pid, so_path)) {
        LOGE("main: inject failed");
        return -1;
    }

    LOGI("main: inject success");
    return 0;
}


