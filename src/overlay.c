/* Original battery overlay: a small display plane above the mirrored video, so the
 * corner shows the battery even when the picture fills the screen. It uses the
 * video sink's own DRM connection, which owns the display while video plays. */
#include "picast_overlay.h"
#include "picast_ui.h"
#include "picast_battery.h"
#include <drm_fourcc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <xf86drm.h>
#include <xf86drmMode.h>

/* The battery service updates every few seconds; plugging in or out should show
 * within about two, so look each second and redraw only on a change. */
#define PC_OVERLAY_CHECK_S 1
#define PC_OVERLAY_REFRESH_S 30

struct buffer { uint32_t handle, fb, pitch; uint64_t size; uint8_t *map; };
struct pc_overlay {
    int fd;
    uint32_t video_plane, plane, crtc;
    unsigned screen_w, screen_h, x, w, h;   /* display mode and battery corner */
    struct buffer b[2];
    int shown, stop;
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t wake;
};

static int make_buffer(int fd, struct buffer *b, unsigned w, unsigned h) {
    struct drm_mode_create_dumb create = {.width = w, .height = h, .bpp = 32};
    if (drmIoctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &create)) return -1;
    b->handle = create.handle; b->pitch = create.pitch; b->size = create.size;
    uint32_t handles[4] = {b->handle}, pitches[4] = {b->pitch}, offsets[4] = {0};
    if (drmModeAddFB2(fd, w, h, DRM_FORMAT_ARGB8888, handles, pitches, offsets, &b->fb, 0)) return -1;
    struct drm_mode_map_dumb map = {.handle = b->handle};
    if (drmIoctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &map)) return -1;
    b->map = mmap(NULL, b->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)map.offset);
    if (b->map == MAP_FAILED) { b->map = NULL; return -1; }
    return 0;
}
static void free_buffer(int fd, struct buffer *b) {
    if (b->map) munmap(b->map, b->size);
    if (b->fb) drmModeRmFB(fd, b->fb);
    if (b->handle) { struct drm_mode_destroy_dumb d = {.handle = b->handle}; drmIoctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &d); }
    memset(b, 0, sizeof(*b));
}
static uint64_t property(int fd, uint32_t plane, const char *name, uint32_t *id, int *mutable_) {
    drmModeObjectProperties *props = drmModeObjectGetProperties(fd, plane, DRM_MODE_OBJECT_PLANE);
    uint64_t value = UINT64_MAX;
    for (uint32_t i = 0; props && i < props->count_props; i++) {
        drmModePropertyRes *p = drmModeGetProperty(fd, props->props[i]);
        if (p && !strcmp(p->name, name)) {
            value = props->prop_values[i];
            if (id) *id = p->prop_id;
            if (mutable_) *mutable_ = !(p->flags & DRM_MODE_PROP_IMMUTABLE);
        }
        drmModeFreeProperty(p);
    }
    drmModeFreeObjectProperties(props);
    return value;
}
/* A free plane on the video's display that takes ARGB and can sit above it. */
static int find_plane(struct pc_overlay *o) {
    drmModePlane *video = drmModeGetPlane(o->fd, o->video_plane);
    if (!video) return -1;
    o->crtc = video->crtc_id;
    drmModeFreePlane(video);
    if (!o->crtc) return -1;
    drmModeCrtc *crtc = drmModeGetCrtc(o->fd, o->crtc);
    if (!crtc || !crtc->mode_valid || !crtc->mode.hdisplay || !crtc->mode.vdisplay) { drmModeFreeCrtc(crtc); return -1; }
    o->screen_w = crtc->mode.hdisplay; o->screen_h = crtc->mode.vdisplay;
    drmModeFreeCrtc(crtc);
    pc_ui_corner(o->screen_w, o->screen_h, &o->x, &o->w, &o->h);
    drmModeRes *res = drmModeGetResources(o->fd);
    int index = -1;
    for (int i = 0; res && i < res->count_crtcs; i++) if (res->crtcs[i] == o->crtc) index = i;
    drmModeFreeResources(res);
    drmModePlaneRes *planes = drmModeGetPlaneResources(o->fd);
    if (index < 0 || !planes) { drmModeFreePlaneResources(planes); return -1; }
    uint64_t video_z = property(o->fd, o->video_plane, "zpos", NULL, NULL);
    for (uint32_t i = 0; i < planes->count_planes && !o->plane; i++) {
        uint32_t id = planes->planes[i];
        drmModePlane *p = drmModeGetPlane(o->fd, id);
        int usable = p && id != o->video_plane && !p->crtc_id && !p->fb_id && (p->possible_crtcs & (1U << index)) &&
                     property(o->fd, id, "type", NULL, NULL) == DRM_PLANE_TYPE_OVERLAY;
        for (uint32_t f = 0; usable && f < p->count_formats; f++)
            if (p->formats[f] == DRM_FORMAT_ARGB8888) usable = 2;
        if (usable == 2) {
            uint32_t zid = 0;
            int zmut = 0;
            uint64_t z = property(o->fd, id, "zpos", &zid, &zmut);
            if (video_z == UINT64_MAX || (z != UINT64_MAX && z > video_z)) o->plane = id;
            else if (zmut && video_z != UINT64_MAX && !drmModeObjectSetProperty(o->fd, id, DRM_MODE_OBJECT_PLANE, zid, video_z + 1)) o->plane = id;
        }
        drmModeFreePlane(p);
    }
    drmModeFreePlaneResources(planes);
    return o->plane ? 0 : -1;
}
/* Draws into the hidden buffer and flips to it; without a battery the plane goes off. */
static void refresh(struct pc_overlay *o) {
    struct buffer *b = &o->b[!o->shown];
    if (pc_ui_battery_overlay(b->map, o->w, o->h, b->pitch, o->screen_w, o->screen_h)) {
        drmModeSetPlane(o->fd, o->plane, o->crtc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        return;
    }
    if (!drmModeSetPlane(o->fd, o->plane, o->crtc, b->fb, 0, (int)o->x, 0, o->w, o->h,
                         0, 0, o->w << 16, o->h << 16))
        o->shown = !o->shown;
}
static void *run(void *arg) {
    struct pc_overlay *o = arg;
    /* The sink sets its plane with the first picture; wait for it, at most 20 s. */
    for (int i = 0; i < 100 && !o->stop && find_plane(o); i++) {
        struct timespec t = {0, 200000000};
        nanosleep(&t, NULL);
    }
    if (o->plane && !make_buffer(o->fd, &o->b[0], o->w, o->h) && !make_buffer(o->fd, &o->b[1], o->w, o->h)) {
        o->shown = 1;
        int last_percent = -2, last_charging = -1, waited = PC_OVERLAY_REFRESH_S;
        pthread_mutex_lock(&o->lock);
        while (!o->stop) {
            pthread_mutex_unlock(&o->lock);
            struct pc_battery b;
            int have = !pc_battery_read(&b);
            int percent = have ? b.percent : -1, charging = have ? b.charging : -1;
            if (percent != last_percent || charging != last_charging || waited >= PC_OVERLAY_REFRESH_S) {
                refresh(o);
                last_percent = percent; last_charging = charging; waited = 0;
            }
            pthread_mutex_lock(&o->lock);
            struct timespec until;
            clock_gettime(CLOCK_REALTIME, &until);
            until.tv_sec += PC_OVERLAY_CHECK_S;
            waited += PC_OVERLAY_CHECK_S;
            while (!o->stop && pthread_cond_timedwait(&o->wake, &o->lock, &until) == 0) {}
        }
        pthread_mutex_unlock(&o->lock);
        drmModeSetPlane(o->fd, o->plane, o->crtc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
    free_buffer(o->fd, &o->b[0]);
    free_buffer(o->fd, &o->b[1]);
    return NULL;
}
struct pc_overlay *pc_overlay_start(int fd, unsigned video_plane) {
    if (fd < 0 || !video_plane) return NULL;
    struct pc_overlay *o = calloc(1, sizeof(*o));
    if (!o) return NULL;
    o->fd = fd; o->video_plane = video_plane;
    pthread_mutex_init(&o->lock, NULL);
    pthread_cond_init(&o->wake, NULL);
    if (pthread_create(&o->thread, NULL, run, o)) {
        pthread_mutex_destroy(&o->lock); pthread_cond_destroy(&o->wake); free(o);
        return NULL;
    }
    return o;
}
void pc_overlay_stop(struct pc_overlay *o) {
    if (!o) return;
    pthread_mutex_lock(&o->lock);
    o->stop = 1;
    pthread_cond_signal(&o->wake);
    pthread_mutex_unlock(&o->lock);
    pthread_join(o->thread, NULL);
    pthread_mutex_destroy(&o->lock);
    pthread_cond_destroy(&o->wake);
    free(o);
}
