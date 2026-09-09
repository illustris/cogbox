#include <libproc.h>
#include <errno.h>
#include <stdint.h>

// Keep the SDK's packed Mach headers out of translate-c.
int cogbox_process(int pid, uint64_t *start, int *parent, int *zombie) {
    struct proc_bsdinfo info;
    int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (n != sizeof(info)) return -1;
    *start = info.pbi_start_tvsec * 1000000 + info.pbi_start_tvusec;
    *parent = (int)info.pbi_ppid;
    *zombie = info.pbi_status == 5;
    return 0;
}
