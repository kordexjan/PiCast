/* Original reader for the INA219 on Waveshare's UPS HAT (C); only reads registers. */
#include "picast_battery.h"
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifdef __linux__
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

/* Resting voltage of a Li-po cell against charge, a common approximation. Under the
 * Pi's load the cell reads a little low, while charging a little high. */
static const struct { double volts; int percent; } curve[] = {
    {3.30, 0}, {3.50, 5}, {3.60, 10}, {3.67, 20}, {3.72, 30}, {3.76, 40},
    {3.80, 50}, {3.86, 60}, {3.93, 70}, {4.00, 80}, {4.08, 90}, {4.18, 100},
};
int pc_battery_percent(double volts) {
    const int n = (int)(sizeof(curve) / sizeof(curve[0]));
    if (volts <= curve[0].volts) return 0;
    if (volts >= curve[n - 1].volts) return 100;
    for (int i = 1; i < n; i++)
        if (volts < curve[i].volts) {
            double f = (volts - curve[i - 1].volts) / (curve[i].volts - curve[i - 1].volts);
            return (int)(curve[i - 1].percent + f * (curve[i].percent - curve[i - 1].percent) + 0.5);
        }
    return 100;
}

/* The cell's own resistance lifts its voltage while charging and lowers it under
 * load. Measured on the board: 3.952 V at -2.53 mV over the shunt, 4.140 V at
 * +4.53 mV; 0.027 V per shunt millivolt (0.27 ohm) brings both to 4.02 V. Under
 * strong charging the voltage stays raised for minutes after, which is why the
 * model below trusts counting over voltage while and after charging. */
double pc_battery_resting_volts(double volts, double shunt_mv) { return volts - shunt_mv * 0.027; }

#define PC_BATTERY_CHARGING_MV 1.0
#define PC_BATTERY_SETTLE_S 1800.0  /* after charging, voltage reads high this long */
#define PC_BATTERY_BLEND_S 3600.0   /* slow pull of the count toward the voltage */
#define PC_BATTERY_LOW_BLEND_S 120.0
void pc_battery_model_init(struct pc_battery_model *m, double saved) {
    *m = (struct pc_battery_model){0};
    if (saved >= 0 && saved <= 100) { m->soc = saved; m->known = 1; m->shown = (int)lround(saved); }
}
int pc_battery_model_step(struct pc_battery_model *m, double volts, double shunt_mv, double dt_s) {
    int charging = shunt_mv > PC_BATTERY_CHARGING_MV;
    double by_voltage = pc_battery_percent(pc_battery_resting_volts(volts, shunt_mv));
    if (!m->known) {
        m->soc = by_voltage; m->known = 1; m->shown = (int)lround(by_voltage);
        m->rested_s = charging ? 0 : PC_BATTERY_SETTLE_S;
    } else {
        if (dt_s < 0 || dt_s > 600) dt_s = 0;  /* a long gap: count nothing, blend below */
        double ma = shunt_mv * PC_BATTERY_MA_PER_MV;
        m->soc += ma * (ma > 0 ? 0.95 : 1.0) * dt_s / 3600.0 / PC_BATTERY_MAH * 100.0;
    }
    m->rested_s = charging ? 0 : m->rested_s + dt_s;
    /* Plugged in, charger finished: full, and still shown as on the cable. */
    int full = volts >= 4.15 && shunt_mv > -0.5 && shunt_mv <= PC_BATTERY_CHARGING_MV;
    if (full) m->soc = 100;
    else if (charging && m->soc > 99) m->soc = 99;
    /* Counting drifts; once settled, the voltage pulls it back slowly, and near
     * empty quickly, so the guard never shuts down late. */
    if (!charging && m->rested_s >= PC_BATTERY_SETTLE_S) {
        double tau = by_voltage < 15 && by_voltage < m->soc ? PC_BATTERY_LOW_BLEND_S : PC_BATTERY_BLEND_S;
        m->soc += (by_voltage - m->soc) * (dt_s < tau ? dt_s / tau : 1.0);
    }
    if (m->soc < 0) m->soc = 0;
    if (m->soc > 100) m->soc = 100;
    /* Shown value: whole steps, and never against the direction of the current. */
    int next = (int)lround(m->soc);
    m->charging = charging || full;
    if ((charging && next > m->shown) || (!charging && next < m->shown) || m->soc == 100) m->shown = next;
    return m->shown;
}

#ifdef __linux__
#define PC_BATTERY_BUS "/dev/i2c-1"
#define PC_BATTERY_ADDRESS 0x43
static int reg(int fd, uint8_t which, int16_t *out) {
    uint8_t b[2];
    if (write(fd, &which, 1) != 1 || read(fd, b, 2) != 2) return -1;
    *out = (int16_t)((uint16_t)b[0] << 8 | b[1]);
    return 0;
}
int pc_battery_sample(double *volts_out, double *shunt_out) {
    int fd = open(PC_BATTERY_BUS, O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    int result = -1;
    if (ioctl(fd, I2C_SLAVE, PC_BATTERY_ADDRESS) == 0) {
        /* Eight quick samples smooth out the Pi's changing load. */
        double volts = 0, shunt = 0;
        int n = 0;
        for (int i = 0; i < 8; i++) {
            int16_t bus, sh;
            if (reg(fd, 0x02, &bus) || reg(fd, 0x01, &sh)) break;
            if (!(bus & 2)) continue;  /* no conversion yet */
            volts += ((uint16_t)bus >> 3) * 0.004;
            shunt += sh * 0.01;
            n++;
            usleep(2000);
        }
        if (n && volts / n > 2.5 && volts / n < 4.5) {
            /* Current into the cell reads positive (Waveshare's documentation). */
            *volts_out = volts / n;
            *shunt_out = shunt / n;
            result = 0;
        }
    }
    close(fd);
    return result;
}
/* The battery service's latest value, if it is fresh. */
static int shared(struct pc_battery *out) {
    FILE *f = fopen(PC_BATTERY_SHARED, "r");
    if (!f) return -1;
    int percent, charging; double volts, shunt; long long at;
    int ok = fscanf(f, "%d %d %lf %lf %lld", &percent, &charging, &volts, &shunt, &at) == 5;
    fclose(f);
    long long now = (long long)time(NULL);
    if (!ok || percent < 0 || percent > 100 || at > now + 5 || now - at > 30) return -1;
    *out = (struct pc_battery){percent, charging != 0, volts, shunt};
    return 0;
}
int pc_battery_read(struct pc_battery *out) {
    const char *preview = getenv("PICAST_BATTERY_PREVIEW");
    if (preview) {  /* Screen previews only: "82" or "82+" for charging. */
        char *end = NULL;
        long p = strtol(preview, &end, 10);
        if (end == preview || p < 0 || p > 100) return -1;
        *out = (struct pc_battery){(int)p, end && *end == '+', 0, 0};
        return 0;
    }
    if (!shared(out)) return 0;
    double volts, shunt;
    if (pc_battery_sample(&volts, &shunt)) return -1;
    out->volts = volts;
    out->shunt_mv = shunt;
    out->charging = shunt > PC_BATTERY_CHARGING_MV;
    out->percent = pc_battery_percent(pc_battery_resting_volts(volts, shunt));
    return 0;
}
#else
int pc_battery_sample(double *volts, double *shunt_mv) { (void)volts; (void)shunt_mv; return -1; }
int pc_battery_read(struct pc_battery *out) { (void)out; return -1; }
#endif
