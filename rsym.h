#pragma once

#include <mach/mach.h>
#include <sys/param.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    mach_vm_address_t base;
    char              path[MAXPATHLEN];
    uint64_t          file_offset;
}image_info;

pid_t get_pid_by_name(const char *name);
bool get_base_address(pid_t pid, const char *image_name, image_info *out);
mach_vm_address_t get_symbol_address(pid_t pid, const char *image_name, const char *symbol_name, bool follow_reexports);

#ifdef __cplusplus
}

inline mach_vm_address_t get_base_address(const char *process_name, const char *image_name)
{
    image_info info;
    pid_t pid = get_pid_by_name(process_name);
    return (pid && get_base_address(pid, image_name, &info)) ? info.base : 0;
}

inline mach_vm_address_t get_base_address(const char *process_name)
{
    return get_base_address(process_name, process_name);
}

inline mach_vm_address_t get_symbol_address(const char *process_name, const char *image_name, const char *symbol_name, bool follow_reexports = true)
{
    pid_t pid = get_pid_by_name(process_name);
    return pid ? get_symbol_address(pid, image_name, symbol_name, follow_reexports) : 0;
}

inline mach_vm_address_t get_symbol_address(const char *process_name, const char *symbol_name, bool follow_reexports = true)
{
    return get_symbol_address(process_name, process_name, symbol_name, follow_reexports);
}

#endif