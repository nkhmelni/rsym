#include "rsym.h"
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>
#include <libkern/OSByteOrder.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

// Unpublished but stable since macOS 10.15
#define PROC_PIDREGIONPATHINFO2 22

#if __arm64__
#define NATIVE_CPU_TYPE CPU_TYPE_ARM64
#ifndef P_TRANSLATED
#define P_TRANSLATED 0x00020000
#endif
#else
#define NATIVE_CPU_TYPE CPU_TYPE_X86_64
#endif

bool _dyld_shared_cache_contains_path(const char *path);
typedef struct mach_header_64 mach_header_64;

// dyld shared cache header (imagesTextOffset/Count)
// legacy fields zeroed in dyld4 I believe
typedef struct
{
    char        magic[16];
    uint32_t    mappingOffset;
    uint32_t    mappingCount;
    uint8_t     _skip[112];
    uint64_t    imagesTextOffset;
    uint64_t    imagesTextCount;
} dyld_cache_header;

typedef struct
{
    uint64_t    address;
    uint64_t    size;
    uint64_t    fileOffset;
    uint32_t    maxProt;
    uint32_t    initProt;
} dyld_cache_mapping_info;

typedef struct
{
    uint8_t     uuid[16];
    uint64_t    loadAddress;
    uint32_t    textSegmentSize;
    uint32_t    pathOffset;
} dyld_cache_image_text_info;

static bool find_base_via_shared_cache(const char *image_name, image_info *out)
{
    uint64_t cache_addr = 0;
    // syscall is deprecated but I prefer it over some more high-level things
    // and yeah there's no other way to use SYS_shared_region_check_np
    if (syscall(SYS_shared_region_check_np, &cache_addr) != 0)
        return false;

    const uint8_t *cache = (const uint8_t *)cache_addr;
    const dyld_cache_header *hdr = (const dyld_cache_header *)cache;
    const dyld_cache_mapping_info *map0 = (const dyld_cache_mapping_info *)(cache + hdr->mappingOffset);
    intptr_t slide = (uintptr_t)cache - map0->address;
    const dyld_cache_image_text_info *images = (const dyld_cache_image_text_info *)(cache + hdr->imagesTextOffset);
    bool by_path = (strchr(image_name, '/') != NULL);

    for (uint64_t i = 0; i < hdr->imagesTextCount; ++i)
    {
        const char *path = (const char *)(cache + images[i].pathOffset);

        if (by_path)
        {
            if (strcmp(path, image_name) != 0)
                continue;
        }
        else
        {
            const char *slash = strrchr(path, '/');
            if (strcmp(slash ? slash + 1 : path, image_name) != 0)
                continue;
        }
        out->base = (mach_vm_address_t)(images[i].loadAddress + slide);
        strlcpy(out->path, path, sizeof(out->path));
        out->file_offset = 0;
        return true;
    }
    return false;
}

static bool find_base_via_proc_info(pid_t pid, const char *image_name, image_info *out)
{
    uint64_t addr = 0;
    struct proc_regionwithpathinfo rpi;
    bool by_path = (strchr(image_name, '/') != NULL);

    for (;;)
    {
        int ret = proc_pidinfo(pid, PROC_PIDREGIONPATHINFO2, addr, &rpi, sizeof(rpi));
        if (ret <= 0)
            break;

        addr = rpi.prp_prinfo.pri_address + rpi.prp_prinfo.pri_size;

        if (!(rpi.prp_prinfo.pri_protection & VM_PROT_EXECUTE))
            continue;

        if (by_path)
        {
            if (strcmp(rpi.prp_vip.vip_path, image_name) != 0)
                continue;
        }
        else
        {
            const char *slash = strrchr(rpi.prp_vip.vip_path, '/');
            const char *basename = slash ? slash + 1 : rpi.prp_vip.vip_path;
            if (strcmp(basename, image_name) != 0)
                continue;
        }

        out->base = (mach_vm_address_t)rpi.prp_prinfo.pri_address;
        strlcpy(out->path, rpi.prp_vip.vip_path, sizeof(out->path));
        out->file_offset = rpi.prp_prinfo.pri_offset;
        return true;
    }
    return false;
}

bool get_base_address(pid_t pid, const char *image_name, image_info *out)
{
    if (!pid)
        return false;
    if (strchr(image_name, '/'))
    {
        // speed up cache enumeration if full path was provided
        if (_dyld_shared_cache_contains_path(image_name))
            return find_base_via_shared_cache(image_name, out);
    }
    else
    {
        if (find_base_via_shared_cache(image_name, out))
            return true;
    }
    return find_base_via_proc_info(pid, image_name, out);
}

static uint64_t read_uleb128(const uint8_t *p, size_t end, size_t *cursor)
{
    uint64_t result = 0;
    int bit = 0;
    while (*cursor < end)
    {
        uint8_t b = p[(*cursor)++];
        result |= (uint64_t)(b & 0x7f) << bit;
        if (!(b & 0x80))
            break;
        bit += 7;
    }
    return result;
}

static uint64_t walk_export_trie(const uint8_t *trie, size_t size, const char *sym, uint32_t *reexport_ord, const char **reexport_name)
{
    const char *s = sym;
    size_t node = 0;

    for (;;)
    {
        if (node >= size)
            return 0;

        size_t cursor = node;
        uint64_t term_size = read_uleb128(trie, size, &cursor);

        if (*s == '\0' && term_size)
        {
            uint64_t flags = read_uleb128(trie, size, &cursor);
            if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT)
            {
                *reexport_ord = (uint32_t)read_uleb128(trie, size, &cursor);
                const char *name = (const char *)(trie + cursor);
                if (*name)
                    *reexport_name = name;
                return 0;
            }
            return read_uleb128(trie, size, &cursor);
        }

        cursor += term_size;
        if (cursor >= size)
            return 0;
        uint8_t nchildren = trie[cursor++];

        size_t next = 0;
        for (uint8_t i = 0; i < nchildren; ++i)
        {
            const char *edge = (const char *)(trie + cursor);
            const char *t = s;
            while (*edge && *t == *edge)
            {
                t++;
                edge++;
            }
            while (cursor < size && trie[cursor])
                cursor++;
            if (cursor >= size)
                return 0;
            cursor++;

            uint64_t child_off = read_uleb128(trie, size, &cursor);

            if (*edge == '\0')
            {
                s = t;
                next = child_off;
                break;
            }
        }
        if (!next)
            return 0;
        node = next;
    }
}

mach_vm_address_t get_symbol_address(pid_t pid, const char *image_name, const char *symbol_name, bool follow_reexports)
{
    image_info info = {0};
    if (!get_base_address(pid, image_name, &info))
        return 0;

    mach_vm_address_t result = 0;
    mach_header_64 *hdr = NULL;
    int fd = -1;
    off_t slice_off = 0;

    if (_dyld_shared_cache_contains_path(info.path))
        hdr = (mach_header_64 *)info.base;
    else
    {
        fd = open(info.path, O_RDONLY);
        if (fd < 0)
            return 0;

        hdr = (mach_header_64 *)malloc(sizeof(mach_header_64));
        slice_off = info.file_offset;
        pread(fd, hdr, sizeof(mach_header_64), slice_off);

        if (hdr->magic == FAT_CIGAM)
        {
            struct fat_header fh;
            memcpy(&fh, hdr, sizeof(fh));
            uint32_t narch = OSSwapBigToHostInt32(fh.nfat_arch);

            cpu_type_t target = NATIVE_CPU_TYPE;
            // try to at least guess the correct slice if running on ARM
            // I suggest you don't run on x86 at all for correctness
#if __arm64__
            struct kinfo_proc kp;
            size_t kp_size = sizeof(kp);
            int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
            if (sysctl(mib, 4, &kp, &kp_size, NULL, 0) == 0 && (kp.kp_proc.p_flag & P_TRANSLATED))
                target = CPU_TYPE_X86_64;
#endif

            for (uint32_t i = 0; i < narch; ++i)
            {
                struct fat_arch fa;
                pread(fd, &fa, sizeof(fa), slice_off + sizeof(fh) + i * sizeof(fa));
                if (OSSwapBigToHostInt32(fa.cputype) == target)
                {
                    slice_off = OSSwapBigToHostInt32(fa.offset);
                    break;
                }
            }
            pread(fd, hdr, sizeof(mach_header_64), slice_off);
        }
        hdr = (mach_header_64 *)realloc(hdr, sizeof(mach_header_64) + hdr->sizeofcmds);
        pread(fd, (uint8_t *)hdr + sizeof(mach_header_64), hdr->sizeofcmds, slice_off + sizeof(mach_header_64));
    }

    const struct load_command *lc = (const struct load_command *)(hdr + 1);
    intptr_t slide = 0;
    uint64_t linkedit_vmaddr = 0, linkedit_fileoff = 0;
    uint32_t export_off = 0, export_size = 0;
    uint32_t ilocalsym = 0, nlocalsym = 0;
    struct symtab_command symtab = {0};

    for (uint32_t i = 0; i < hdr->ncmds; ++i)
    {
        if (lc->cmd == LC_SEGMENT_64)
        {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (!strcmp(seg->segname, "__TEXT"))
            {
                slide = (uintptr_t)info.base - seg->vmaddr;
                if (strncmp(symbol_name, "sub_", 4) == 0)
                {
                    mach_vm_address_t addr = strtoull(symbol_name + 4, NULL, 16);
                    if (fd >= 0)
                    {
                        free(hdr);
                        close(fd);
                    }
                    return addr + slide;
                }
            }
            else if (!strcmp(seg->segname, "__LINKEDIT"))
            {
                linkedit_vmaddr = seg->vmaddr;
                linkedit_fileoff = seg->fileoff;
            }
        }
        else if (lc->cmd == LC_SYMTAB)
            symtab = *(const struct symtab_command *)lc;
        else if (lc->cmd == LC_DYLD_EXPORTS_TRIE)
        {
            const struct linkedit_data_command *led = (const struct linkedit_data_command *)lc;
            export_off = led->dataoff;
            export_size = led->datasize;
        }
        else if (lc->cmd == LC_DYLD_INFO_ONLY)
        {
            const struct dyld_info_command *dic = (const struct dyld_info_command *)lc;
            export_off = dic->export_off;
            export_size = dic->export_size;
        }
        else if (lc->cmd == LC_DYSYMTAB)
        {
            const struct dysymtab_command *dst = (const struct dysymtab_command *)lc;
            ilocalsym = dst->ilocalsym;
            nlocalsym = dst->nlocalsym;
        }
        lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
    }

    // all exported symbols (pretty informative since symbols that aren't stripped
    // are often exported or re-exported)
    if (export_size)
    {
        uint8_t *trie;

        if (fd < 0)
            trie = (uint8_t *)(linkedit_vmaddr + slide - linkedit_fileoff + export_off);
        else
        {
            trie = (uint8_t *)malloc(export_size);
            pread(fd, trie, export_size, slice_off + export_off);
        }

        uint32_t reexport_ord = 0;
        const char *reexport_name = NULL;

        result = walk_export_trie(trie, export_size, symbol_name, &reexport_ord, &reexport_name);
        if (!result && !reexport_ord)
        {
            char prefixed[256];
            snprintf(prefixed, sizeof(prefixed), "_%s", symbol_name);
            result = walk_export_trie(trie, export_size, prefixed, &reexport_ord, &reexport_name);
        }

        if (reexport_ord && follow_reexports)
        {
            lc = (const struct load_command *)(hdr + 1);
            uint32_t dep = 0;
            char target_path[MAXPATHLEN] = {0};
            char import[256] = {0};

            for (uint32_t i = 0; i < hdr->ncmds; ++i)
            {
                if (lc->cmd == LC_LOAD_DYLIB || lc->cmd == LC_LOAD_WEAK_DYLIB || lc->cmd == LC_REEXPORT_DYLIB || lc->cmd == LC_LAZY_LOAD_DYLIB)
                {
                    if (++dep == reexport_ord)
                    {
                        const char *name = (const char *)lc + ((const struct dylib_command *)lc)->dylib.name.offset;
                        strlcpy(target_path, name, sizeof(target_path));
                        break;
                    }
                }
                lc = (const struct load_command *)((const uint8_t *)lc + lc->cmdsize);
            }

            if (reexport_name)
                strlcpy(import, reexport_name, sizeof(import));

            if (fd >= 0)
            {
                free(trie);
                free(hdr);
                close(fd);
            }

            if (!target_path[0])
                return 0;
            return get_symbol_address(pid, target_path, import[0] ? import : symbol_name, true);
        }

        if (fd >= 0)
            free(trie);
        if (result)
            result += info.base;
    }

    if (!result)
    {
        uintptr_t linkedit_base;
        uint8_t *symdata = NULL;

        if (fd < 0)
            linkedit_base = linkedit_vmaddr + slide - linkedit_fileoff;
        else
        {
            size_t nl_size = symtab.nsyms * sizeof(struct nlist_64);
            size_t total = (symtab.stroff - symtab.symoff) + symtab.strsize;
            symdata = (uint8_t *)malloc(total);
            pread(fd, symdata, nl_size, slice_off + symtab.symoff);
            pread(fd, symdata + (symtab.stroff - symtab.symoff), symtab.strsize, slice_off + symtab.stroff);
            linkedit_base = (uintptr_t)symdata - symtab.symoff;
        }

        const struct nlist_64 *nl = (const struct nlist_64 *)(linkedit_base + symtab.symoff);
        const char *strtab = (const char *)(linkedit_base + symtab.stroff);

        for (uint32_t i = ilocalsym; i < ilocalsym + nlocalsym; ++i)
        {
            if ((nl[i].n_type & N_TYPE) != N_SECT)
                continue;

            const char *name = strtab + nl[i].n_un.n_strx;
            if (!strcmp(name, symbol_name) || (name[0] == '_' && !strcmp(name + 1, symbol_name)))
            {
                result = nl[i].n_value + slide;
                break;
            }
        }
        free(symdata);
    }

    if (fd >= 0)
    {
        free(hdr);
        close(fd);
    }
    return result;
}

pid_t get_pid_by_name(const char *name)
{
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0)
        return 0;
    size += size / 4;

    struct kinfo_proc *procs = (struct kinfo_proc *)malloc(size);
    if (sysctl(mib, 4, procs, &size, NULL, 0) < 0)
    {
        free(procs);
        return 0;
    }

    int nprocs = (int)(size / sizeof(struct kinfo_proc));
    size_t name_len = strlen(name);
    pid_t result = 0;

    if (name_len < MAXCOMLEN)
    {
        for (int i = 0; i < nprocs; ++i)
        {
            if (strcasecmp(procs[i].kp_proc.p_comm, name) == 0)
            {
                result = procs[i].kp_proc.p_pid;
                break;
            }
        }
    }
    else
    {
        for (int i = 0; i < nprocs; ++i)
        {
            if (strncasecmp(procs[i].kp_proc.p_comm, name, MAXCOMLEN) != 0)
                continue;

            char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
            pid_t pid = procs[i].kp_proc.p_pid;
            if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) <= 0)
                continue;

            const char *slash = strrchr(pathbuf, '/');
            const char *bin = slash ? slash + 1 : pathbuf;
            if (strcasecmp(bin, name) == 0)
            {
                result = pid;
                break;
            }
        }
    }
    free(procs);
    return result;
}
