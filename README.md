# rsym

Resolve symbol addresses in remote macOS processes at runtime — without `task_for_pid`, without injecting code and reading remote memory.

rsym parses Mach-O metadata through the dyld shared cache and on-disk files to turn `(process, image, symbol)` into a live virtual address. It works against hardened runtime, SIP-protected, and system processes alike, and requires no special permissions on macOS.

**Note:** rsym gives you addresses, NOT access. Reading data at these addresses still requires a task port — unless the image is in the shared cache, which is mapped identically in every process. Even for cache images, reading access DOES NOT mean writing access outside of the host process.

## Build

```bash
mkdir build
cd build
cmake ..
make
```

Produces `rsym` (CLI) and `librsym.a` (static C library).

## Usage

```bash
# Symbol address
rsym Finder libsystem_c.dylib printf

# Image base address
rsym Finder libsystem_c.dylib

# Re-exported symbol (strcmp re-exports through libsystem_platform)
rsym Finder libsystem_c.dylib strcmp

# Framework symbol
rsym Finder AppKit _NSApp

# Stripped symbol (unslid virtual address in hex)
rsym SomeApp SomeApp sub_100003A20
```

## API

### C

```c
#include "rsym.h"

pid_t pid = get_pid_by_name("Finder");

// Resolve image base address (full metadata)
image_info info;
if (get_base_address(pid, "libsystem_c.dylib", &info))
    printf("base: 0x%llx  path: %s\n", info.base, info.path);

// Resolve symbol address
mach_vm_address_t addr = get_symbol_address(pid, "libsystem_c.dylib", "printf", true);
```

| Function | Description |
|---|---|
| `pid_t get_pid_by_name(const char *name)` | Find a process by name. Case-insensitive. Returns 0 on failure. |
| `bool get_base_address(pid_t pid, const char *image_name, image_info *out)` | Resolve the runtime base address, on-disk path, and file offset of a loaded image. |
| `mach_vm_address_t get_symbol_address(pid_t pid, const char *image_name, const char *symbol_name, bool follow_reexports)` | Resolve the runtime address of a symbol. Pass `true` for `follow_reexports` to chase re-export chains across dylibs. |

`image_name` can be a full path (`/usr/lib/system/libsystem_c.dylib`) or a basename (`libsystem_c.dylib`).

### C++

The header provides inline overloads when compiled as C++, which is much more convenient and user-friendly:

```cpp
#include "rsym.h"

// By process name — resolves PID internally
mach_vm_address_t base = get_base_address("Finder", "libsystem_c.dylib");
mach_vm_address_t addr = get_symbol_address("Finder", "libsystem_c.dylib", "printf");

// Image name defaults to process name
mach_vm_address_t self_base = get_base_address("MyApp");
mach_vm_address_t self_sym  = get_symbol_address("MyApp", "some_func");
```

## How it works

No remote memory is ever read, though `proc_*` calls allow to glance at foreign runtime. All Mach-O parsing is done locally — either from the in-process shared cache mapping (equally available for all processes) or via `pread` on the on-disk binary (reading isn't restricted on macOS).

**Shared cache images** (~3000 system dylibs): A single syscall (`shared_region_check_np`) obtains the cache base address, which is mapped read-only at the same virtual address in every process. The cache header contains a complete image table with addresses and paths. ASLR slide is derived from the first mapping entry and applies uniformly. Zero file I/O.

**Non-cache images** (app binaries, plugins, standalone dylibs): `proc_pidinfo` with flavor 22 (`PROC_PIDREGIONPATHINFO2`) walks VM regions. The kernel skips anonymous mappings, so only vnode-backed executable regions are visited — typically 10-50x fewer syscalls than a full region scan. The matched on-disk path is then opened for Mach-O parsing via `open` and `pread`.

**Symbol resolution** follows a layered strategy:
1. **Export trie** — O(k) prefix-trie walk where k is the symbol name length. Covers all exported symbols. Checks `LC_DYLD_EXPORTS_TRIE`, falls back to `LC_DYLD_INFO_ONLY`.
2. **Re-export following** — If the trie indicates a re-export, the ordinal is resolved to a dependent dylib via `LC_LOAD_DYLIB` counting, and resolution recurses into that dylib, so the most original function address is resolved (optional).
3. **Nlist fallback** — Scans only local symbols (`ilocalsym`/`nlocalsym` from `LC_DYSYMTAB`), since the trie already covers exports at all times.
4. **Stripped addresses** — Symbols matching `sub_XXXX` are treated as unslid virtual addresses and have the ASLR slide applied directly, so `sub_XXXX` function names obtained from IDA or other disassemblers can be matched with ASLR and returned as an actual runtime address in the specified image.

## Notes

- **Identical processes**: `get_pid_by_name` picks one arbitrarily when multiple processes share the same name. Use the `pid_t`-based C API directly if you need a specific instance.
- **Architecture**: Works for both ARM and x86 targets, but for non-cache images, would mislead if the target runs natively on ARM and the remote process runs under Rosetta — rsym would choose the x86 slice regardless.
- **Permissions**: No entitlements, root, or SIP exceptions are needed on macOS for same-user processes. Wasn't tested in a very restricted sandbox, but a signed user process works just fine.
- **macOS version**: Requires macOS 10.15+ (shared cache image text info fields and `PROC_PIDREGIONPATHINFO2` flavor).
