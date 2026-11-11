/* Original low-battery guard for the UPS HAT: notice on screen, then a clean
 * power-off through systemd while the cell still has a margin. */
#include "picast_guard.h"
#include "picast_ui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int pc_guard_step(struct pc_guard *g, const struct pc_battery *b) {
    if (!b) return g->low >= PC_GUARD_READINGS;  /* no reading: keep the count */
    if (b->charging || b->percent > PC_GUARD_PERCENT) g->low = 0;
    else g->low++;
    return g->low >= PC_GUARD_READINGS;
}

#define PC_GUARD_NOTICE_S 10
#define PC_GUARD_STATE_DIR "/var/lib/picast"
#define PC_GUARD_STATE PC_GUARD_STATE_DIR "/battery-state"
#define PC_GUARD_LOG PC_GUARD_STATE_DIR "/battery-log.csv"
#define PC_GUARD_LOG_LIMIT (2L << 20)
#define PC_GUARD_LOG_S 60

/* The counted charge survives restarts; written only when the shown value moves,
 * so the memory card sees a few writes an hour. */
static double load_state(void) {
    FILE *f = fopen(PC_GUARD_STATE, "r");
    double soc = -1; long long at = 0;
    if (f) {
        if (fscanf(f, "%lf %lld", &soc, &at) != 2) soc = -1;
        fclose(f);
    }
    /* Older than a day: the cell may have been swapped or charged elsewhere. */
    if (soc < 0 || soc > 100 || (long long)time(NULL) - at > 86400) return -1;
    return soc;
}
/* Where the count starts. Right after power-on the cell has been resting while
 * the Pi was off, so its voltage is the most reliable measure there is (only the
 * small boot load to allow for); the saved count only wins while charging, when
 * the voltage reads high, or when just the service restarted. */
#define PC_GUARD_BOOT_S 300.0
static double start_value(double saved) {
    double uptime = 1e9, volts, shunt;
    FILE *f = fopen("/proc/uptime", "r");
    if (f) { if (fscanf(f, "%lf", &uptime) != 1) uptime = 1e9; fclose(f); }
    if (uptime > PC_GUARD_BOOT_S) return saved;
    if (pc_battery_sample(&volts, &shunt)) return saved;
    if (shunt <= 1.0) return -1;  /* resting at power-on: start from the voltage */
    return saved;
}
static void write_atomic(const char *path, const char *text) {
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "%s.new", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    int ok = fputs(text, f) >= 0;
    ok = fflush(f) == 0 && ok;
    if (fclose(f) || !ok || rename(tmp, path)) unlink(tmp);
}
static void log_line(const struct pc_battery *b, double soc) {
    struct stat st;
    if (!stat(PC_GUARD_LOG, &st) && st.st_size > PC_GUARD_LOG_LIMIT) rename(PC_GUARD_LOG, PC_GUARD_LOG ".1");
    FILE *f = fopen(PC_GUARD_LOG, "a");
    if (!f) return;
    fprintf(f, "%lld,%.3f,%.2f,%.2f,%d,%d\n", (long long)time(NULL), b->volts, b->shunt_mv, soc, b->percent, b->charging);
    fclose(f);
}

int pc_guard_run(int dry_run, unsigned interval_s) {
    struct pc_guard g = {0};
    struct pc_battery_model model;
    if (!dry_run) mkdir(PC_GUARD_STATE_DIR, 0755);
    pc_battery_model_init(&model, dry_run ? -1 : start_value(load_state()));
    struct timespec last = {0};
    time_t last_log = 0;
    int saved = -1, drawn_percent = -1, drawn_charging = -1;
    for (;;) {
        struct pc_battery b = {0};
        double volts, shunt;
        const char *preview = getenv("PICAST_BATTERY_PREVIEW");
        int have;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (preview) have = !pc_battery_read(&b);  /* simulated readings for tests */
        else if ((have = !pc_battery_sample(&volts, &shunt))) {
            double dt = last.tv_sec ? (double)(now.tv_sec - last.tv_sec) + (now.tv_nsec - last.tv_nsec) / 1e9 : 0;
            b.volts = volts; b.shunt_mv = shunt;
            b.percent = pc_battery_model_step(&model, volts, shunt, dt);
            b.charging = model.charging;
            last = now;
            char text[96];
            snprintf(text, sizeof(text), "%d %d %.3f %.2f %lld\n", b.percent, b.charging, volts, shunt, (long long)time(NULL));
            write_atomic(PC_BATTERY_SHARED, text);
            /* The receiver's own screens show the corner at once; above video the
             * overlay picks the change up within a second. */
            if (!dry_run && (b.percent != drawn_percent || b.charging != drawn_charging)) {
                pc_ui_refresh_battery();
                drawn_percent = b.percent; drawn_charging = b.charging;
            }
            if (!dry_run && b.percent != saved) {
                snprintf(text, sizeof(text), "%.3f %lld\n", model.soc, (long long)time(NULL));
                write_atomic(PC_GUARD_STATE, text);
                saved = b.percent;
            }
            if (!dry_run && time(NULL) - last_log >= PC_GUARD_LOG_S) { log_line(&b, model.soc); last_log = time(NULL); }
        }
        int due = pc_guard_step(&g, have ? &b : NULL);
        if (dry_run) {
            printf("{\"event\":\"battery_guard_reading\",\"read\":%s,\"percent\":%d,\"charging\":%s,\"volts\":%.3f,\"shunt_mv\":%.2f,\"low_readings\":%d}\n",
                   have ? "true" : "false", have ? b.percent : -1, have && b.charging ? "true" : "false", b.volts, b.shunt_mv, g.low);
            fflush(stdout);
        }
        if (due) break;
        sleep(interval_s);
    }
    /* The notice stays up while the system stops; video, if any, ends with it. */
    int shown = pc_ui_show(PC_UI_LOW_BATTERY, NULL, NULL) == 0;
    printf("{\"event\":\"battery_guard_shutdown\",\"notice_shown\":%s,\"dry_run\":%s}\n", shown ? "true" : "false", dry_run ? "true" : "false");
    fflush(stdout);
    sleep(PC_GUARD_NOTICE_S);
    if (dry_run) return 0;
    sync();
    execlp("systemctl", "systemctl", "poweroff", (char *)NULL);
    perror("systemctl poweroff");
    return 1;
}
