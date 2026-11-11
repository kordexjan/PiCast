/* Original PiCast screens, drawn with Cairo. Inter is the only font; no third-party artwork. */
#include "picast_ui.h"
#include "picast_battery.h"
#include "picast_config.h"
#include <cairo/cairo.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <linux/kd.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

/* Screens are laid out on a 1920 x 1080 canvas, scaled to fit any display and
 * centred on it; the battery stays in the display's own top right corner. */
#define UI_WIDTH 1920
#define UI_HEIGHT 1080
#define UI_MAX_SIDE 4096
#define UI_FONT "Inter"
#define UI_BACKGROUND 0x0b0b0d
#define UI_STATE "/run/picast-ui-screen"

static double fit(unsigned width, unsigned height) {
    double sx = width / (double)UI_WIDTH, sy = height / (double)UI_HEIGHT;
    return sx < sy ? sx : sy;
}
void pc_ui_corner(unsigned width, unsigned height, unsigned *x, unsigned *w, unsigned *h) {
    double s = fit(width, height);
    unsigned cw = (unsigned)ceil(PC_UI_BATTERY_W * s), ch = (unsigned)ceil(PC_UI_BATTERY_H * s);
    if (cw > width) cw = width;
    if (ch > height) ch = height;
    *x = width - cw; *w = cw; *h = ch;
}
/* Canvas coordinates of the battery, anchored to the display's top right corner. */
static void corner_space(cairo_t *c, unsigned width, unsigned height) {
    double s = fit(width, height);
    cairo_translate(c, width - UI_WIDTH * s, 0);
    cairo_scale(c, s, s);
}

static void color(cairo_t *c, unsigned rgb) {
    cairo_set_source_rgb(c, (rgb >> 16 & 255) / 255.0, (rgb >> 8 & 255) / 255.0, (rgb & 255) / 255.0);
}
static void rounded(cairo_t *c, double x, double y, double w, double h, double r) {
    cairo_new_sub_path(c);
    cairo_arc(c, x + w - r, y + r, r, -M_PI / 2, 0);
    cairo_arc(c, x + w - r, y + h - r, r, 0, M_PI / 2);
    cairo_arc(c, x + r, y + h - r, r, M_PI / 2, M_PI);
    cairo_arc(c, x + r, y + r, r, M_PI, 3 * M_PI / 2);
    cairo_close_path(c);
}
/* Centred text, made smaller where it would leave the canvas (a long name). */
static void centered(cairo_t *c, const char *text, double size, int bold, unsigned rgb, double center_x, double baseline) {
    cairo_text_extents_t e;
    cairo_select_font_face(c, UI_FONT, CAIRO_FONT_SLANT_NORMAL, bold ? CAIRO_FONT_WEIGHT_BOLD : CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(c, size);
    cairo_text_extents(c, text, &e);
    if (e.width > UI_WIDTH - 240) {
        cairo_set_font_size(c, size * (UI_WIDTH - 240) / e.width);
        cairo_text_extents(c, text, &e);
    }
    color(c, rgb);
    cairo_move_to(c, center_x - e.width / 2 - e.x_bearing, baseline);
    cairo_show_text(c, text);
}

/* Everything the screens say, in English and German (picast.txt: language). */
enum text_id {
    T_STARTING, T_RADIO, T_DRIVER, T_READY_1, T_READY_2, T_PIN, T_PIN_NOTE, T_CONNECTING,
    T_RECOVERING, T_RECOVERING_NOTE, T_LOW, T_LOW_NOTE, T_LOW_HINT, T_COUNT
};
static const char *const texts[2][T_COUNT] = {
    [PC_LANGUAGE_EN] = {
        "Starting …", "Turning on the radio …", "Setting up for the new system, this takes a few minutes …",
        "Open Screen Mirroring", "on your iPhone, iPad or Mac", "Enter this code on your device",
        "Only needed the first time", "Connecting", "Restoring the connection", "PiCast will be right back",
        "Battery almost empty", "PiCast is turning off now", "Connect the charger to keep using it",
    },
    [PC_LANGUAGE_DE] = {
        "Startet …", "Funk wird eingeschaltet …", "Wird für das neue System eingerichtet, das dauert einige Minuten …",
        "Öffne auf deinem iPhone oder Mac", "die Bildschirmsynchronisierung", "Gib diesen Code auf deinem Gerät ein",
        "Nur beim ersten Verbinden nötig", "Verbinde", "Verbindung wird wiederhergestellt", "PiCast ist gleich wieder da",
        "Akku fast leer", "PiCast schaltet sich jetzt aus", "Zum Weiternutzen das Ladekabel anschließen",
    },
};
static const char *say(enum text_id id) { return texts[pc_ui_language() == PC_LANGUAGE_DE][id]; }
/* The starting screen's status line: a known step by its key, else the text itself. */
static const char *status_line(const char *text) {
    if (!text || !*text) return say(T_STARTING);
    if (!strcmp(text, "radio")) return say(T_RADIO);
    if (!strcmp(text, "driver")) return say(T_DRIVER);
    return text;
}
/* A screen with arcs rising from its lower left corner. */
static void cast_mark(cairo_t *c, double cx, double cy, double size) {
    double x = cx - size / 2, y = cy - size * 0.4, w = size, h = size * 0.8;
    color(c, 0xa1a1a6);
    cairo_set_line_width(c, size * 0.055);
    cairo_set_line_cap(c, CAIRO_LINE_CAP_ROUND);
    double r = size * 0.09, gap = size * 0.3;
    cairo_new_path(c);
    cairo_move_to(c, x, y + h - gap);
    cairo_line_to(c, x, y + r);
    cairo_arc(c, x + r, y + r, r, M_PI, 3 * M_PI / 2);
    cairo_line_to(c, x + w - r, y);
    cairo_arc(c, x + w - r, y + r, r, -M_PI / 2, 0);
    cairo_line_to(c, x + w, y + h - r);
    cairo_arc(c, x + w - r, y + h - r, r, 0, M_PI / 2);
    cairo_line_to(c, x + gap, y + h);
    cairo_stroke(c);
    for (int i = 1; i <= 2; i++) {
        cairo_arc(c, x, y + h, size * 0.14 * i, -M_PI / 2, 0);
        cairo_stroke(c);
    }
    cairo_arc(c, x, y + h, size * 0.035, 0, 2 * M_PI);
    cairo_fill(c);
}
static void dots(cairo_t *c, double cx, double cy) {
    color(c, 0xa1a1a6);
    for (int i = -1; i <= 1; i++) {
        cairo_arc(c, cx + i * 36, cy, 9, 0, 2 * M_PI);
        cairo_fill(c);
    }
}
/* Battery glyph and percentage, drawn small and grey so it stays in the background.
 * Red at 20 % and below, green with a bolt while charging. Above video (pill set)
 * a dark translucent pill keeps it readable on bright pictures. */
static void battery(cairo_t *c, const struct pc_battery *b, int pill) {
    const double right = UI_WIDTH - 38, top = 32, w = 44, h = 21, r = 6;
    double x = right - 4 - w;
    unsigned fill = b->charging ? 0x30d158 : b->percent <= 20 ? 0xff453a : 0xa1a1a6;
    char text[8];
    snprintf(text, sizeof(text), "%d %%", b->percent);
    cairo_text_extents_t e;
    cairo_select_font_face(c, UI_FONT, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(c, 23);
    cairo_text_extents(c, text, &e);
    double tx = x - 12 - e.x_advance, bx = tx - 19, left = b->charging ? bx : tx;
    if (pill) {
        cairo_set_source_rgba(c, 0, 0, 0, 0.55);
        rounded(c, left - 15, top - 11, right + 15 - (left - 15), h + 22, (h + 22) / 2);
        cairo_fill(c);
    }
    color(c, pill ? 0x8e8e93 : 0x6e6e73);
    cairo_set_line_width(c, 2);
    rounded(c, x, top, w, h, r);
    cairo_stroke(c);
    rounded(c, right - 2.2, top + h / 2 - 4, 3.5, 8, 1.6);
    cairo_fill(c);
    double inner = (w - 7) * (b->percent < 4 ? 4 : b->percent) / 100.0;
    color(c, fill);
    rounded(c, x + 3.5, top + 3.5, inner, h - 7, 3.5);
    cairo_fill(c);
    if (b->charging) {
        double by = top - 1;  /* lightning bolt, 14 x 23 */
        color(c, 0x30d158);
        cairo_new_path(c);
        cairo_move_to(c, bx + 8.8, by);
        cairo_line_to(c, bx + 0.9, by + 13.3);
        cairo_line_to(c, bx + 6.6, by + 13.3);
        cairo_line_to(c, bx + 4.4, by + 23);
        cairo_line_to(c, bx + 13.2, by + 8.8);
        cairo_line_to(c, bx + 7.5, by + 8.8);
        cairo_close_path(c);
        cairo_fill(c);
    }
    /* Nearly empty: the number turns red too, so the warning reads from across the room. */
    color(c, !b->charging && b->percent <= 10 ? 0xff453a : pill ? 0xc7c7cc : 0x86868b);
    cairo_move_to(c, tx, top + h / 2 + 8.3);
    cairo_show_text(c, text);
}
static void draw(cairo_t *c, unsigned width, unsigned height, enum pc_ui_screen screen, const char *text, const char *caption, int bare) {
    double mid = UI_WIDTH / 2.0, s = fit(width, height);
    color(c, screen == PC_UI_BLANK ? 0 : UI_BACKGROUND);
    cairo_paint(c);
    cairo_set_antialias(c, CAIRO_ANTIALIAS_BEST);
    cairo_save(c);
    cairo_translate(c, (width - UI_WIDTH * s) / 2, (height - UI_HEIGHT * s) / 2);
    cairo_scale(c, s, s);
    switch (screen) {
    case PC_UI_STARTING:
        cast_mark(c, mid, 400, 110);
        centered(c, pc_receiver_name(), 92, 1, 0xf5f5f7, mid, 560);
        centered(c, status_line(text), 36, 0, 0xa1a1a6, mid, 650);
        break;
    case PC_UI_READY:
        cast_mark(c, mid, 400, 110);
        centered(c, pc_receiver_name(), 92, 1, 0xf5f5f7, mid, 560);
        centered(c, say(T_READY_1), 36, 0, 0xa1a1a6, mid, 650);
        centered(c, say(T_READY_2), 36, 0, 0xa1a1a6, mid, 700);
        break;
    case PC_UI_PIN: {
        centered(c, say(T_PIN), 40, 0, 0xa1a1a6, mid, 370);
        const double tile_w = 150, tile_h = 200, gap = 28, left = mid - (4 * tile_w + 3 * gap) / 2;
        for (int i = 0; i < 4; i++) {
            double x = left + i * (tile_w + gap);
            char digit[2] = {text && strlen(text) == 4 ? text[i] : ' ', 0};
            color(c, 0x1c1c1f);
            rounded(c, x, 430, tile_w, tile_h, 26);
            cairo_fill(c);
            centered(c, digit, 112, 1, 0xf5f5f7, x + tile_w / 2, 572);
        }
        centered(c, say(T_PIN_NOTE), 30, 0, 0x86868b, mid, 720);
        break;
    }
    case PC_UI_CONNECTING:
        dots(c, mid, 470);
        centered(c, say(T_CONNECTING), 60, 1, 0xf5f5f7, mid, 590);
        break;
    case PC_UI_RECOVERING:
        dots(c, mid, 450);
        centered(c, say(T_RECOVERING), 54, 1, 0xf5f5f7, mid, 570);
        centered(c, say(T_RECOVERING_NOTE), 36, 0, 0xa1a1a6, mid, 640);
        break;
    case PC_UI_LOW_BATTERY: {
        const double w = 240, h = 110, x = mid - w / 2 - 8, y = 330;
        color(c, 0x6e6e73);
        cairo_set_line_width(c, 6);
        rounded(c, x, y, w, h, 26);
        cairo_stroke(c);
        rounded(c, x + w + 8, y + h / 2 - 20, 14, 40, 6);
        cairo_fill(c);
        color(c, 0xff453a);
        rounded(c, x + 14, y + 14, 26, h - 28, 12);
        cairo_fill(c);
        centered(c, say(T_LOW), 72, 1, 0xf5f5f7, mid, 570);
        centered(c, say(T_LOW_NOTE), 36, 0, 0xa1a1a6, mid, 650);
        centered(c, say(T_LOW_HINT), 30, 0, 0x86868b, mid, 710);
        break;
    }
    case PC_UI_BLANK:
        break;
    }
    cairo_restore(c);
    if (caption && *caption) {
        cairo_save(c);
        cairo_translate(c, 0, height - UI_HEIGHT * s);
        cairo_scale(c, s, s);
        cairo_select_font_face(c, UI_FONT, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(c, 22);
        color(c, 0x6e6e73);
        cairo_move_to(c, 32, UI_HEIGHT - 32);
        cairo_show_text(c, caption);
        cairo_restore(c);
    }
    /* Also on the blank screen behind the video: the picture leaves the corner free
     * (bars above a landscape mirror, beside a portrait one). */
    struct pc_battery b;
    if (!bare && screen != PC_UI_LOW_BATTERY && !pc_battery_read(&b)) {
        corner_space(c, width, height);
        battery(c, &b, 0);
    }
}
int pc_ui_battery_overlay(unsigned char *argb, unsigned width, unsigned height, unsigned stride,
                          unsigned screen_w, unsigned screen_h) {
    struct pc_battery b;
    int have = !pc_battery_read(&b);
    cairo_surface_t *s = cairo_image_surface_create_for_data(argb, CAIRO_FORMAT_ARGB32, (int)width, (int)height, (int)stride);
    cairo_t *c = cairo_create(s);
    cairo_set_operator(c, CAIRO_OPERATOR_CLEAR);
    cairo_paint(c);
    cairo_set_operator(c, CAIRO_OPERATOR_OVER);
    cairo_set_antialias(c, CAIRO_ANTIALIAS_BEST);
    unsigned x0, cw, ch;
    pc_ui_corner(screen_w, screen_h, &x0, &cw, &ch);
    cairo_translate(c, -(double)x0, 0);
    corner_space(c, screen_w, screen_h);
    if (have) battery(c, &b, 1);
    cairo_surface_flush(s);
    int ok = cairo_status(c) == CAIRO_STATUS_SUCCESS;
    cairo_destroy(c);
    cairo_surface_destroy(s);
    return have && ok ? 0 : -1;
}
int pc_ui_write_png(enum pc_ui_screen screen, const char *text, const char *caption, const char *path,
                    unsigned width, unsigned height) {
    if (!width || !height || width > UI_MAX_SIDE || height > UI_MAX_SIDE) return -1;
    cairo_surface_t *s = cairo_image_surface_create(CAIRO_FORMAT_RGB24, (int)width, (int)height);
    cairo_t *c = cairo_create(s);
    draw(c, width, height, screen, text, caption, 0);
    int ok = cairo_status(c) == CAIRO_STATUS_SUCCESS && cairo_surface_write_to_png(s, path) == CAIRO_STATUS_SUCCESS;
    cairo_destroy(c);
    cairo_surface_destroy(s);
    return ok ? 0 : -1;
}
/* Stops the console from drawing over the screens: no cursor, no kernel messages. */
static void console_mode(int mode) {
    int fd = open("/dev/tty1", O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) return;
    if (ioctl(fd, KDSETMODE, mode)) { /* Without a console the screens still work. */ }
    close(fd);
}
struct paint { enum pc_ui_screen screen; const char *text, *caption; int corner, bare; };
static void paint(cairo_t *c, const struct paint *p, unsigned width, unsigned height, unsigned x0) {
    if (!p->corner) { draw(c, width, height, p->screen, p->text, p->caption, p->bare); return; }
    struct pc_battery b;
    color(c, p->screen == PC_UI_BLANK ? 0 : UI_BACKGROUND);
    cairo_paint(c);
    cairo_set_antialias(c, CAIRO_ANTIALIAS_BEST);
    cairo_translate(c, -(double)x0, 0);
    corner_space(c, width, height);
    if (!pc_battery_read(&b)) battery(c, &b, 0);
}
/* Draws the whole screen, or with corner set only the battery area, into /dev/fb0. */
static int show(const struct paint *p) {
    int fd = open("/dev/fb0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    struct fb_var_screeninfo v;
    struct fb_fix_screeninfo f;
    int result = -1;
    /* Whatever mode the display came up in: the screens scale to it. */
    if (ioctl(fd, FBIOGET_VSCREENINFO, &v) || ioctl(fd, FBIOGET_FSCREENINFO, &f) || !v.xres || !v.yres ||
        v.xres > UI_MAX_SIDE || v.yres > UI_MAX_SIDE || (v.bits_per_pixel != 16 && v.bits_per_pixel != 32)) goto done;
    uint8_t *map = mmap(NULL, f.smem_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) goto done;
    unsigned cx, cw, ch;
    pc_ui_corner(v.xres, v.yres, &cx, &cw, &ch);
    size_t x0 = p->corner ? cx : 0, w = p->corner ? cw : v.xres, h = p->corner ? ch : v.yres;
    if ((size_t)f.line_length * v.yres <= f.smem_len && (size_t)v.xres * (v.bits_per_pixel / 8) <= f.line_length) {
        /* Drawn off screen first, so a picture never appears half finished. */
        cairo_format_t format = v.bits_per_pixel == 16 ? CAIRO_FORMAT_RGB16_565 : CAIRO_FORMAT_RGB24;
        cairo_surface_t *s = cairo_image_surface_create(format, (int)w, (int)h);
        cairo_t *c = cairo_create(s);
        paint(c, p, v.xres, v.yres, (unsigned)x0);
        cairo_surface_flush(s);
        if (cairo_status(c) == CAIRO_STATUS_SUCCESS) {
            const uint8_t *from = cairo_image_surface_get_data(s);
            size_t stride = (size_t)cairo_image_surface_get_stride(s), pixel = v.bits_per_pixel / 8;
            if (!p->corner) console_mode(KD_GRAPHICS);
            for (size_t y = 0; y < h; y++) memcpy(map + y * f.line_length + x0 * pixel, from + y * stride, w * pixel);
            result = 0;
        }
        cairo_destroy(c);
        cairo_surface_destroy(s);
    }
    munmap(map, f.smem_len);
done:
    close(fd);
    return result;
}
/* Only the kind of screen is kept, never the PIN, so a refresh knows whether the
 * battery belongs on screen. */
static void remember(enum pc_ui_screen screen) {
    FILE *f = fopen(UI_STATE, "w");
    if (!f) return;
    fprintf(f, "%d\n", (int)screen);
    fclose(f);
}
int pc_ui_show(enum pc_ui_screen screen, const char *text, const char *caption) {
    struct paint p = {screen, text, caption, 0, 0};
    int result = show(&p);
    if (result) unlink(UI_STATE);
    else remember(screen);
    return result;
}
int pc_ui_refresh_battery(void) {
    FILE *f = fopen(UI_STATE, "r");
    int screen = -1;
    if (f) {
        if (fscanf(f, "%d", &screen) != 1) screen = -1;
        fclose(f);
    }
    if (screen < PC_UI_READY || screen > PC_UI_STARTING || screen == PC_UI_LOW_BATTERY) return 0;
    struct paint p = {(enum pc_ui_screen)screen, NULL, NULL, 1, 0};
    return show(&p);
}
void pc_ui_release(void) {
    struct paint p = {PC_UI_BLANK, NULL, NULL, 0, 1};
    if (show(&p)) { /* Without a display there is nothing to hand back. */ }
    unlink(UI_STATE);
    console_mode(KD_TEXT);
}
static int parse_screen(const char *name, enum pc_ui_screen *screen) {
    static const char *const names[] = {"ready", "pin", "connecting", "recovering", "lowbattery", "blank", "starting"};
    for (int i = 0; i < 7; i++) if (!strcmp(name, names[i])) { *screen = (enum pc_ui_screen)i; return 0; }
    return -1;
}
/* picast ui SCREEN [TEXT]; picast ui off; picast ui battery;
 * picast ui-png SCREEN TEXT OUT.png [WIDTHxHEIGHT]. TEXT is the PIN, or the status
 * line of the starting screen: radio, driver or any text. */
int pc_ui_command(int argc, char **argv) {
    enum pc_ui_screen screen;
    if (argc == 3 && !strcmp(argv[1], "ui") && !strcmp(argv[2], "off")) { pc_ui_release(); return 0; }
    if (argc == 3 && !strcmp(argv[1], "ui") && !strcmp(argv[2], "battery")) return pc_ui_refresh_battery() ? 1 : 0;
    if (argc >= 3 && argc <= 4 && !strcmp(argv[1], "ui") && !parse_screen(argv[2], &screen))
        return pc_ui_show(screen, argc == 4 ? argv[3] : NULL, NULL) ? 1 : 0;
    if ((argc == 5 || argc == 6) && !strcmp(argv[1], "ui-png") && !parse_screen(argv[2], &screen)) {
        unsigned width = UI_WIDTH, height = UI_HEIGHT;
        if (argc == 6 && sscanf(argv[5], "%ux%u", &width, &height) != 2) return 2;
        return pc_ui_write_png(screen, argv[3], NULL, argv[4], width, height) ? 1 : 0;
    }
    return 2;
}
