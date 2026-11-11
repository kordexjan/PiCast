#ifndef PICAST_BATTERY_H
#define PICAST_BATTERY_H
/* Optional battery board (Waveshare UPS HAT (C): one Li-po cell, INA219 at I2C 0x43).
 * Without the board every reading fails and the screens show no battery. */
struct pc_battery { int percent, charging; double volts, shunt_mv; };
/* The charge to show: from the battery service (picast-power) when it runs, which
 * counts charge in and out, else straight from the voltage. */
int pc_battery_read(struct pc_battery *);
/* Raw reading from the board: cell voltage and shunt millivolts, + while charging. */
int pc_battery_sample(double *volts, double *shunt_mv);
/* Charge estimate for one Li-po cell from its resting voltage, 0..100. */
int pc_battery_percent(double volts);
/* Resting voltage from a reading under load or charge. */
double pc_battery_resting_volts(double volts, double shunt_mv);
#define PC_BATTERY_SHARED "/run/picast-battery"

/* Charge counting between voltage checks. The board's shunt is 0.01 ohm, so one
 * shunt millivolt is 100 mA; the cell Waveshare names is 1000 mAh. */
#define PC_BATTERY_MA_PER_MV 100.0
#define PC_BATTERY_MAH 1000.0
struct pc_battery_model {
    double soc;          /* 0..100, counted */
    int known, shown, charging;
    double rested_s;     /* time since charging stopped; voltage needs it to settle */
};
/* With saved >= 0 the count continues from a stored value, else it starts from
 * the voltage at the first step. */
void pc_battery_model_init(struct pc_battery_model *, double saved);
/* One reading dt_s after the previous one. Returns the percent to show, which
 * only falls while discharging and only rises while charging. */
int pc_battery_model_step(struct pc_battery_model *, double volts, double shunt_mv, double dt_s);
#endif
