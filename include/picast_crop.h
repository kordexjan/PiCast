#ifndef PICAST_CROP_H
#define PICAST_CROP_H
#include <stddef.h>
#include <stdint.h>
/* Black-border removal for mirrored video: an app's 16:9 picture inside the
 * wider iPhone screen arrives with black bars, which the display then frames
 * with its own. Detection reads the luma plane; the tracker decides slowly to
 * crop and quickly to show more again. */
struct pc_crop_box { unsigned x,y,w,h; };
struct pc_crop_tracker { unsigned width,height,agree; struct pc_crop_box shown,pending; };
/* Bounding box of the non-black picture. -1 if the frame is too dark to tell. */
int pc_crop_detect(const uint8_t *luma,size_t stride,unsigned width,unsigned height,struct pc_crop_box *content);
/* Whether anything bright appears in the area a crop hides: an app left its
 * fullscreen player, so everything should show again soon, even when the rest of
 * the new screen is too dark to measure. */
int pc_crop_bars_lit(const uint8_t *luma,size_t stride,unsigned width,unsigned height,const struct pc_crop_box *shown);
void pc_crop_reset(struct pc_crop_tracker *,unsigned width,unsigned height);
/* Feed one detection (NULL: no decision). Returns 1 when `shown` changed. */
int pc_crop_update(struct pc_crop_tracker *,const struct pc_crop_box *content);
int pc_crop_is_full(const struct pc_crop_tracker *);
#endif
