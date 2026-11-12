#ifndef PICAST_CONFIG_H
#define PICAST_CONFIG_H
#include <stddef.h>
/* Settings a user edits on any computer: picast.txt on the SD card's boot
 * partition ("bootfs"). Lines "key = value"; "#" starts a comment. Anything
 * missing or invalid keeps its default, so a broken file never stops the receiver. */
#define PC_CONFIG_PATH "/boot/firmware/picast.txt"
/* Older installs switched maintenance on with an empty file of this name. */
#define PC_CONFIG_MAINTENANCE_FLAG "/boot/firmware/picast-maintenance"
#define PC_CONFIG_NAME_MAX 40       /* bytes; the AirPlay menu shows it */
#define PC_CONFIG_DELAY_DEFAULT 270 /* ms; r229/r231: smooth with a little margin */
#define PC_CONFIG_DELAY_MIN 100
#define PC_CONFIG_DELAY_MAX 500
/* WLAN country (ISO 3166 code). Without one, the radio stays in a restricted
 * worldwide mode in which Apple devices do not find PiCast. PiCast transmits
 * only on 2.4 GHz channel 6, which every country allows. */
#define PC_CONFIG_COUNTRY_DEFAULT "DE"

enum pc_language { PC_LANGUAGE_EN, PC_LANGUAGE_DE };
struct pc_config {
    char name[PC_CONFIG_NAME_MAX + 1];
    enum pc_language language;
    unsigned delay_ms;
    char country[3];                   /* two capital letters */
    int maintenance;
    unsigned warnings;                 /* lines that were ignored */
    char warning[4][96];               /* the first few, for `picast config` */
};
void pc_config_defaults(struct pc_config *);
/* Applies the text of a settings file on top of the current values. */
void pc_config_parse(struct pc_config *, const char *text, size_t size);
/* Defaults, then the file at path (NULL: PICAST_CONFIG or PC_CONFIG_PATH) and the
 * old maintenance flag. Never fails: a missing file means defaults. */
void pc_config_load(struct pc_config *, const char *path);
/* A name the AirPlay menu can show: 1..40 bytes of valid UTF-8, no control
 * characters, quotes or backslashes, not only spaces. */
int pc_config_name_valid(const char *name);
/* The receiver's name for the AirPlay menu and the screens: PICAST_NAME if
 * valid, else the settings file's (default "PiCast"). */
const char *pc_receiver_name(void);
/* The language for screens: PICAST_LANGUAGE (en/de) if set, else the settings file. */
enum pc_language pc_ui_language(void);
/* picast config [show]: settings as one JSON line.
 * picast config maintenance: exit 0 in maintenance mode, 1 otherwise.
 * picast config receiver: the opposite (for systemd's ExecCondition). */
int pc_config_command(int argc, char **argv);
#endif
