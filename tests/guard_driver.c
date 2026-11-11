#include "picast_guard.h"
#include <stdio.h>

#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); return 1; } } while (0)

/* Feeds n readings; returns whether the last one asked for shutdown and that no
 * earlier one did. */
static int feed(struct pc_guard *g, const struct pc_battery *b, int n) {
    for (int i = 0; i < n - 1; i++) if (pc_guard_step(g, b)) return -1;
    return pc_guard_step(g, b);
}

int main(void) {
    const int n = PC_GUARD_READINGS;
    struct pc_guard g = {0};
    struct pc_battery low = {4, 0, 3.45, -2.5}, ok = {40, 0, 3.75, -2.5}, charging = {3, 1, 3.75, 11.0};
    /* n low readings in a row shut down; fewer do not. */
    CHECK(feed(&g, &low, n) == 1);
    g.low = 0;
    CHECK(feed(&g, &low, n - 1) == 0);
    /* A good reading in between starts over. */
    CHECK(!pc_guard_step(&g, &ok));
    CHECK(feed(&g, &low, n - 1) == 0);
    CHECK(pc_guard_step(&g, &low));
    /* Charging is never a reason to shut down, however low. */
    g.low = 0;
    CHECK(feed(&g, &charging, 3 * n) == 0);
    /* A failed reading neither counts nor resets. */
    g.low = 0;
    CHECK(feed(&g, &low, n - 1) == 0);
    CHECK(!pc_guard_step(&g, NULL));
    CHECK(pc_guard_step(&g, &low));
    /* Exactly at the threshold counts, one above does not. */
    struct pc_battery edge = {PC_GUARD_PERCENT, 0, 3.5, -2}, above = {PC_GUARD_PERCENT + 1, 0, 3.5, -2};
    g.low = 0;
    CHECK(feed(&g, &above, 3 * n) == 0);
    CHECK(feed(&g, &edge, n) == 1);
    printf("guard tests passed\n");
    return 0;
}
