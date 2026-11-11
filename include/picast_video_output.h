#ifndef PICAST_VIDEO_OUTPUT_H
#define PICAST_VIDEO_OUTPUT_H
#include <stdint.h>
#include <stddef.h>
struct pc_playout;
void *pc_video_output_open(int headless);
void *pc_video_output_open_timed(int headless, const struct pc_playout *);
int pc_video_output_push(void *,const uint8_t *,size_t,int config);
int pc_video_output_push_at(void *,const uint8_t *,size_t,int config,uint64_t pts);
int pc_video_output_step(void *);
int pc_video_output_end(void *);
void pc_video_output_stats(void *,unsigned *,unsigned *,unsigned *);
void pc_video_output_delivery_stats(void *,uint64_t *rendered,uint64_t *dropped);
/* How often black-bar removal changed, and the last shown area (0 when never cropped). */
/* Pictures compared, those off their sender spacing by more than 34 ms, by more
 * than 100 ms, and the worst deviation. */
void pc_video_output_pacing_stats(void *,unsigned *paced,unsigned *uneven,unsigned *stalls,unsigned *worst_ms);
/* Whether pictures wait for their due time (the default) or show once decoded. */
int pc_video_timed(void);
void pc_video_output_crop_stats(void *,unsigned *changes,unsigned *width,unsigned *height);
void pc_video_output_close(void *);
/* Initialize plugin discovery before entering the time-sensitive radio loop. */
void pc_video_output_prepare(void);
#endif
