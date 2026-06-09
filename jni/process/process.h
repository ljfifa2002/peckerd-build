#ifndef ATTACH_INJECTOR_PROCESS_PROCESS_H
#define ATTACH_INJECTOR_PROCESS_PROCESS_H

#include <sys/types.h>
#include <cstdint>
#include <vector>

int get_pid(const char* process_name);
// Return every zygote process to hook for spawn injection.  Matches processes
// whose cmdline is exactly "zygote" or "zygote64", filtered by ABI via
// /proc/<pid>/exe (app_process64 vs app_process32).  On OPPO/ColorOS the
// fast-start zygote (init service "zygote_HBT") runs as a SEPARATE process named
// just "zygote" — same name as the 32-bit zygote — so it can only be told apart
// by ABI.  want64=true returns 64-bit zygotes (zygote64 + the 64-bit fast-start
// "zygote"); want64=false returns 32-bit ones.
std::vector<pid_t> get_zygote_pids(bool want64);
long get_module_base(pid_t pid, const char* module_name);
const char* get_module_name(pid_t pid, uintptr_t addr);
long get_remote_addr(pid_t pid, void* local_func);

#endif // ATTACH_INJECTOR_PROCESS_PROCESS_H
