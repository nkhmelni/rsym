#include "rsym.h"
#include <stdio.h>

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "usage: %s <process> <image> <symbol>\n", argv[0]);
        return 1;
    }

    const char *process = argv[1];
    const char *image = argv[2];
    const char *symbol = argc > 3 ? argv[3] : NULL;

    pid_t pid = get_pid_by_name(process);
    if (!pid)
    {
        fprintf(stderr, "process not found: %s\n", process);
        return 1;
    }

    if (symbol)
    {
        mach_vm_address_t addr = get_symbol_address(pid, image, symbol, true);
        if (addr)
        {
            printf("0x%llx\n", (unsigned long long)addr);
            return 0;
        }
        fprintf(stderr, "symbol not found\n");
        return 1;
    }

    image_info info;
    if (get_base_address(pid, image, &info))
    {
        printf("0x%llx\n", (unsigned long long)info.base);
        return 0;
    }

    fprintf(stderr, "not found\n");
    return 1;
}
