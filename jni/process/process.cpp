#include "process.h"
#include "../common/log.h"

#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

int get_pid(const char* process_name) {
    if (process_name == nullptr || process_name[0] == '\0') {
        LOGE("get_pid: invalid process name");
        return -1;
    }

    DIR* dir = opendir("/proc");
    if (dir == nullptr) {
        LOGE("get_pid: failed to open /proc");
        return -1;
    }

    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        int pid = atoi(entry->d_name);
        if (pid <= 0) {
            continue;
        }

        char path[256] = {0};
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

        FILE* fp = fopen(path, "r");
        if (fp == nullptr) {
            continue;
        }

        char cmdline[256] = {0};
        fgets(cmdline, sizeof(cmdline), fp);
        fclose(fp);

        char* name = strrchr(cmdline, '/');
        if (name == nullptr) {
            name = cmdline;
        } else {
            name++;
        }

        if (strcmp(process_name, name) == 0) {
            closedir(dir);
            LOGI("get_pid: found pid=%d for process=%s", pid, process_name);
            return pid;
        }
    }

    closedir(dir);
    LOGE("get_pid: process not found: %s", process_name);
    return -1;
}

std::vector<pid_t> get_zygote_pids(bool want64) {
    std::vector<pid_t> result;

    DIR* dir = opendir("/proc");
    if (dir == nullptr) {
        LOGE("get_zygote_pids: failed to open /proc");
        return result;
    }

    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        int pid = atoi(entry->d_name);
        if (pid <= 0) {
            continue;
        }

        // argv[0] — zygote sets it to "zygote"/"zygote64" via setArgV0.  The OPPO
        // fast-start zygote is a separate process whose cmdline is just "zygote",
        // so we accept both names and disambiguate the 32- vs 64-bit ones by ABI.
        char path[256] = {0};
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        FILE* fp = fopen(path, "r");
        if (fp == nullptr) {
            continue;
        }
        char cmdline[256] = {0};
        if (fgets(cmdline, sizeof(cmdline), fp) == nullptr) {
            fclose(fp);
            continue;
        }
        fclose(fp);

        char* name = strrchr(cmdline, '/');
        name = (name == nullptr) ? cmdline : name + 1;
        if (strcmp(name, "zygote") != 0 && strcmp(name, "zygote64") != 0) {
            continue;  // excludes webview_zygote / app_zygote / everything else
        }

        // ABI filter via the ELF class of /proc/<pid>/exe.  We can't match on the
        // binary name: the OPPO fast-start zygote runs /system_ext/bin/hbt_translator
        // (cmdline "zygote", 64-bit) — NOT app_process64 — so name-matching the exe
        // would miss it.  Read the ELF header's EI_CLASS byte instead (1 = 32-bit,
        // 2 = 64-bit).  The arm64 build must only inject the arm64 ncore into 64-bit
        // zygotes (zygote64 + the 64-bit fast-start "zygote").
        char exe_path[64] = {0};
        snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);

        char exe_target[256] = {0};
        ssize_t ln = readlink(exe_path, exe_target, sizeof(exe_target) - 1);
        if (ln > 0) {
            exe_target[ln] = '\0';
        }

        int efd = open(exe_path, O_RDONLY | O_CLOEXEC);
        if (efd < 0) {
            continue;
        }
        unsigned char ehdr[5] = {0};
        ssize_t rd = read(efd, ehdr, sizeof(ehdr));
        close(efd);
        if (rd < 5 || ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F') {
            continue;
        }
        bool is64 = (ehdr[4] == 2);  // ELFCLASS64
        if (is64 != want64) {
            continue;
        }

        result.push_back(pid);
        LOGI("get_zygote_pids: matched name=%s pid=%d exe=%s class=%d-bit",
             name, pid, exe_target, is64 ? 64 : 32);
    }

    closedir(dir);
    if (result.empty()) {
        LOGE("get_zygote_pids: no %d-bit zygote found", want64 ? 64 : 32);
    }
    return result;
}

int kill_usap_processes(bool want64) {
    // ColorOS keeps the USAP pool alive even after usap_pool_enabled=false, and the
    // blanks pre-forked at boot (before ncore was injected into the zygote) carry NO
    // ncore hooks.  If the target app is specialised from such a blank it escapes
    // ncore entirely -> the spawn callback times out (~20s) and the task retries.
    // Draining the pool right before `am start` forces the app to either cold-fork
    // from the (now hooked) zygote or grab a freshly re-forked, hooked blank.  One
    // pass suffices: any blank re-forked afterwards comes from the hooked zygote and
    // installs child hooks before it is offered to the pool.  A blank that has
    // already specialised no longer has cmdline "usap64"/"usap32", so matching the
    // exact cmdline only ever hits still-blank slots.
    const char* want_name = want64 ? "usap64" : "usap32";
    int killed = 0;

    DIR* dir = opendir("/proc");
    if (dir == nullptr) {
        LOGE("kill_usap_processes: failed to open /proc");
        return 0;
    }

    struct dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        int pid = atoi(entry->d_name);
        if (pid <= 0) {
            continue;
        }

        char path[256] = {0};
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        FILE* fp = fopen(path, "r");
        if (fp == nullptr) {
            continue;
        }
        char cmdline[256] = {0};
        char* got = fgets(cmdline, sizeof(cmdline), fp);
        fclose(fp);
        if (got == nullptr) {
            continue;
        }

        // cmdline is NUL-separated; a blank slot's whole cmdline is just the name.
        if (strcmp(cmdline, want_name) != 0) {
            continue;
        }

        if (kill(pid, SIGKILL) == 0) {
            killed++;
            LOGI("kill_usap_processes: killed %s pid=%d", want_name, pid);
        }
    }

    closedir(dir);
    LOGI("kill_usap_processes: drained %d %s blank(s)", killed, want_name);
    return killed;
}

long get_module_base(pid_t pid, const char* module_name) {
    if (module_name == nullptr || module_name[0] == '\0') {
        LOGE("get_module_base: invalid module name");
        return 0;
    }

    char maps_path[64] = {0};
    if (pid == -1) {
        snprintf(maps_path, sizeof(maps_path), "/proc/self/maps");
    } else {
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    }

    FILE* fp = fopen(maps_path, "r");
    if (fp == nullptr) {
        LOGE("get_module_base: failed to open %s", maps_path);
        return 0;
    }

    char line[512] = {0};
    long base_addr = 0;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        if (strstr(line, module_name) != nullptr) {
            char* start = strtok(line, "-");
            if (start != nullptr) {
                base_addr = strtoul(start, nullptr, 16);
                break;
            }
        }
    }

    fclose(fp);

    if (base_addr == 0) {
        LOGE("get_module_base: module not found: %s, pid=%d", module_name, pid);
    } else {
        LOGD("get_module_base: module=%s pid=%d base=%lx", module_name, pid, base_addr);
    }

    return base_addr;
}

const char* get_module_name(pid_t pid, uintptr_t addr) {
    char maps_path[64] = {0};
    if (pid == -1) {
        snprintf(maps_path, sizeof(maps_path), "/proc/self/maps");
    } else {
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    }

    FILE* fp = fopen(maps_path, "r");
    if (fp == nullptr) {
        LOGE("get_module_name: failed to open %s", maps_path);
        return nullptr;
    }

    char line[1024] = {0};
    while (fgets(line, sizeof(line), fp) != nullptr) {
        unsigned long start_l = 0, end_l = 0;
        if (sscanf(line, "%lx-%lx", &start_l, &end_l) != 2) {
            continue;
        }
        uintptr_t start = static_cast<uintptr_t>(start_l);
        uintptr_t end   = static_cast<uintptr_t>(end_l);

        if (addr >= start && addr < end) {
            char* path = strchr(line, '/');
            if (path != nullptr) {
                char* newline = strchr(path, '\n');
                if (newline != nullptr) {
                    *newline = '\0';
                }
                fclose(fp);
                LOGD("get_module_name: addr=%lx module=%s", (unsigned long) addr, path);
                return strdup(path);
            }
        }
    }

    fclose(fp);
    LOGE("get_module_name: module not found for addr=%lx", (unsigned long) addr);
    return nullptr;
}

long get_remote_addr(pid_t pid, void* local_func) {
    if (local_func == nullptr) {
        LOGE("get_remote_addr: local_func is null");
        return 0;
    }

    const char* module_path = get_module_name(-1, reinterpret_cast<uintptr_t>(local_func));
    if (module_path == nullptr) {
        LOGE("get_remote_addr: failed to get local module name");
        return 0;
    }

    long local_base = get_module_base(-1, module_path);
    long remote_base = get_module_base(pid, module_path);
    if (local_base == 0 || remote_base == 0) {
        LOGE("get_remote_addr: failed to get module base, module=%s local=%lx remote=%lx",
             module_path, local_base, remote_base);
        return 0;
    }

    long remote_addr = reinterpret_cast<long>(local_func) - local_base + remote_base;
    LOGD("get_remote_addr: module=%s local_func=%lx local_base=%lx remote_base=%lx remote_addr=%lx",
         module_path, reinterpret_cast<long>(local_func), local_base, remote_base, remote_addr);
    return remote_addr;
}
