#ifndef ATTACH_INJECTOR_PROCESS_PROCESS_H
#define ATTACH_INJECTOR_PROCESS_PROCESS_H

#include <sys/types.h>
#include <cstdint>
#include <vector>

int get_pid(const char* process_name);
// Return every zygote process to hook for spawn injection.  Matches processes
// whose cmdline is exactly "zygote" or "zygote64", filtered by ABI via the ELF
// class of /proc/<pid>/exe.  On OPPO/ColorOS the fast-start zygote (init service
// "zygote_HBT") runs as a SEPARATE process with cmdline "zygote" — same as the
// 32-bit zygote — whose exe is /system_ext/bin/hbt_translator (NOT app_process64),
// so it can only be told apart by ABI, read from the ELF header rather than the
// binary name.  want64=true returns 64-bit zygotes (zygote64 + the 64-bit
// fast-start "zygote"); want64=false returns 32-bit ones.
std::vector<pid_t> get_zygote_pids(bool want64);
// Kill unspecialised USAP pool blanks (cmdline exactly "usap64"/"usap32").  ColorOS
// keeps the pool alive after usap_pool_enabled=false and boot-time blanks have no
// ncore hooks, so an app specialised from one escapes injection.  Call right before
// `am start` to force the app to fork from the hooked zygote.  Returns the count
// killed; harmless (returns 0) on devices without a USAP pool.
int kill_usap_processes(bool want64);
long get_module_base(pid_t pid, const char* module_name);
const char* get_module_name(pid_t pid, uintptr_t addr);
long get_remote_addr(pid_t pid, void* local_func);

#endif // ATTACH_INJECTOR_PROCESS_PROCESS_H
