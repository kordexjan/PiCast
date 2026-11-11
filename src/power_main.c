/* picast-power: the always-on battery side of the receiver, separate from the
 * radio so it keeps working whatever the mirroring part does.
 *   picast-power guard [--dry-run] [--interval SECONDS]
 *   picast-power ui ...   (same screens as picast ui, for checking) */
#include "picast_guard.h"
#include "picast_ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "guard")) {
        int dry = 0;
        unsigned interval = PC_GUARD_INTERVAL_S;
        for (int i = 2; i < argc; i++) {
            if (!strcmp(argv[i], "--dry-run")) dry = 1;
            else if (!strcmp(argv[i], "--interval") && i + 1 < argc) {
                long v = strtol(argv[++i], NULL, 10);
                if (v < 1 || v > 600) goto usage;
                interval = (unsigned)v;
            } else goto usage;
        }
        return pc_guard_run(dry, interval);
    }
    if (argc >= 3 && (!strcmp(argv[1], "ui") || !strcmp(argv[1], "ui-png"))) {
        int r = pc_ui_command(argc, argv);
        if (r != 2) return r;
    }
usage:
    fprintf(stderr, "usage: picast-power guard [--dry-run] [--interval SECONDS] | picast-power ui SCREEN\n");
    return 2;
}
