#ifndef PICAST_GUARD_H
#define PICAST_GUARD_H
/* Shuts the receiver down cleanly before the battery cuts the power, so the
 * memory card is never left half written. */
#include "picast_battery.h"

#define PC_GUARD_PERCENT 5   /* at or below, while not charging */
#define PC_GUARD_READINGS 30  /* in a row (30 s), so one dip under load does not count */
#define PC_GUARD_INTERVAL_S 1   /* also the charge-counting step; plugging in shows within ~2 s */

struct pc_guard { int low; };
/* One reading, or NULL when the battery could not be read (which never counts
 * towards a shutdown). Returns 1 once the receiver should shut down. */
int pc_guard_step(struct pc_guard *, const struct pc_battery *);
/* Reads every interval until shutdown is due, shows the notice, then powers off.
 * With dry_run set it prints what it would do instead of powering off. */
int pc_guard_run(int dry_run, unsigned interval_s);
#endif
