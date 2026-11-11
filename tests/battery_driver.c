/* Charge curve only; no I2C access. */
#include "picast_battery.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    assert(pc_battery_percent(2.9) == 0 && pc_battery_percent(3.30) == 0);
    assert(pc_battery_percent(4.25) == 100 && pc_battery_percent(4.18) == 100);
    assert(pc_battery_percent(3.80) == 50 && pc_battery_percent(4.00) == 80);
    assert(pc_battery_percent(3.83) == 55);
    for (double v = 3.0, last = -1; v < 4.3; v += 0.01) {
        int p = pc_battery_percent(v);
        assert(p >= last && p >= 0 && p <= 100);
        last = p;
    }
    /* Model: starts from the voltage, then counts. 250 mA (-2.5 mV) for 25 minutes
     * of a 1000 mAh cell is 10.4 points (no voltage pull before settling). */
    struct pc_battery_model m;
    pc_battery_model_init(&m, -1);
    int p0 = pc_battery_model_step(&m, 3.952, -2.53, 0);
    assert(p0 >= 82 && p0 <= 83);
    int p = p0;
    m.rested_s = 0;
    for (int i = 0; i < 300; i++) {  /* 25 min in 5 s steps */
        int q = pc_battery_model_step(&m, 3.952, -2.5, 5);
        assert(q <= p);
        p = q;
    }
    assert(p >= p0 - 11 && p <= p0 - 10);
    /* Plugging in: the voltage jumps, the shown value does not; it then rises with
     * the charge counted (1 A for 6 min = 100 mAh * 0.95 = 9.5 points). */
    int before = p;
    int c = pc_battery_model_step(&m, 4.14, 10.0, 5);
    assert(c == before);
    for (int i = 0; i < 72; i++) { int q = pc_battery_model_step(&m, 4.14, 10.0, 5); assert(q >= c); c = q; }
    assert(c >= before + 9 && c <= before + 11);
    /* Unplugging right after: voltage reads high for minutes, the value stays put
     * rather than jumping up, and then only falls. */
    int u = pc_battery_model_step(&m, 4.05, -2.5, 5);
    assert(u <= c);
    for (int i = 0; i < 120; i++) { int q = pc_battery_model_step(&m, 4.05 - i * 0.0005, -2.5, 5); assert(q <= u); u = q; }
    /* Charger done at the top: full. */
    struct pc_battery_model f;
    pc_battery_model_init(&f, 90);
    assert(pc_battery_model_step(&f, 4.17, 0.2, 5) == 100);
    /* Near empty the voltage wins within minutes, so shutdown is not late. */
    struct pc_battery_model e;
    pc_battery_model_init(&e, 30);
    e.rested_s = 4000;
    int last = 30;
    for (int i = 0; i < 120; i++) last = pc_battery_model_step(&e, 3.45, -2.5, 5);  /* 10 min */
    assert(last <= 8);
    puts("battery: charge curve bounds, points and monotony passed");
    return 0;
}
