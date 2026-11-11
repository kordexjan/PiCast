#ifndef PICAST_OVERLAY_H
#define PICAST_OVERLAY_H
/* Battery corner above the video, refreshed every 30 s from its own thread.
 * fd and video_plane are the video sink's; stop before the sink closes. */
struct pc_overlay;
struct pc_overlay *pc_overlay_start(int fd, unsigned video_plane);
void pc_overlay_stop(struct pc_overlay *);
#endif
