#ifndef PICAST_UI_H
#define PICAST_UI_H
/* The receiver's own screens on the HDMI output, shown whenever no video plays. */
/* Top right corner holding the battery, on the 1920 x 1080 layout canvas. */
#define PC_UI_BATTERY_W 360
#define PC_UI_BATTERY_H 120
/* New screens go last: the battery service reads the shown screen's number. */
enum pc_ui_screen { PC_UI_READY, PC_UI_PIN, PC_UI_CONNECTING, PC_UI_RECOVERING, PC_UI_LOW_BATTERY, PC_UI_BLANK, PC_UI_STARTING };
/* The battery corner of a display of this size, in its pixels. */
void pc_ui_corner(unsigned width, unsigned height, unsigned *x, unsigned *w, unsigned *h);
/* text is the PIN for PC_UI_PIN, the status line for PC_UI_STARTING (a step key:
 * radio or driver; "Starting …" when NULL) and unused otherwise; caption is an
 * optional small line at the bottom. Returns 0 once the screen is visible, -1
 * without a display. */
int pc_ui_show(enum pc_ui_screen screen, const char *text, const char *caption);
/* Hands the display back to the text console. */
void pc_ui_release(void);
/* Redraws only the battery corner while PiCast owns the display, video included. */
int pc_ui_refresh_battery(void);
/* Battery corner for the plane above video on a screen_w x screen_h display
 * (pc_ui_corner gives its size): premultiplied ARGB, transparent around it.
 * -1 without a battery reading. */
int pc_ui_battery_overlay(unsigned char *argb, unsigned width, unsigned height, unsigned stride,
                          unsigned screen_w, unsigned screen_h);
int pc_ui_write_png(enum pc_ui_screen screen, const char *text, const char *caption, const char *path,
                    unsigned width, unsigned height);
int pc_ui_command(int argc, char **argv);
#endif
