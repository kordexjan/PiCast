/* The user's settings file on the boot partition. */
#include "picast_config.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

void pc_config_defaults(struct pc_config *c) {
    memset(c, 0, sizeof(*c));
    strcpy(c->name, "PiCast");
    c->language = PC_LANGUAGE_EN;
    c->delay_ms = PC_CONFIG_DELAY_DEFAULT;
    strcpy(c->country, PC_CONFIG_COUNTRY_DEFAULT);
}

/* Strict UTF-8: no overlong forms, surrogates or code points above U+10FFFF. */
static int utf8_valid(const unsigned char *s, size_t n) {
    for (size_t i = 0; i < n;) {
        unsigned char c = s[i];
        size_t len = c < 0x80 ? 1 : (c & 0xe0) == 0xc0 ? 2 : (c & 0xf0) == 0xe0 ? 3 : (c & 0xf8) == 0xf0 ? 4 : 0;
        if (!len || i + len > n) return 0;
        unsigned long cp = len == 1 ? c : len == 2 ? c & 0x1f : len == 3 ? c & 0x0f : c & 0x07;
        for (size_t k = 1; k < len; k++) {
            if ((s[i + k] & 0xc0) != 0x80) return 0;
            cp = cp << 6 | (s[i + k] & 0x3f);
        }
        static const unsigned long least[] = {0, 0, 0x80, 0x800, 0x10000};
        if (cp < least[len] || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return 0;
        i += len;
    }
    return 1;
}
int pc_config_name_valid(const char *name) {
    if (!name) return 0;
    size_t n = strlen(name);
    if (!n || n > PC_CONFIG_NAME_MAX || !utf8_valid((const unsigned char *)name, n)) return 0;
    int visible = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c < 0x20 || c == 0x7f || c == '"' || c == '\\') return 0;
        if (c != ' ') visible = 1;
    }
    return visible;
}

static void warn(struct pc_config *c, unsigned line, const char *what) {
    if (c->warnings < sizeof(c->warning) / sizeof(c->warning[0]))
        snprintf(c->warning[c->warnings], sizeof(c->warning[0]), "line %u: %s", line, what);
    c->warnings++;
}
static int switch_value(const char *v, int *out) {
    static const char *const on[] = {"on", "yes", "true", "1"}, *const off[] = {"off", "no", "false", "0"};
    for (size_t i = 0; i < 4; i++) {
        if (!strcasecmp(v, on[i])) { *out = 1; return 0; }
        if (!strcasecmp(v, off[i])) { *out = 0; return 0; }
    }
    return -1;
}
static void apply(struct pc_config *c, unsigned line, const char *key, char *value) {
    size_t n = strlen(value);
    /* A value may be quoted, to keep spaces at its ends. */
    if (n >= 2 && ((value[0] == '"' && value[n - 1] == '"') || (value[0] == '\'' && value[n - 1] == '\''))) {
        value[n - 1] = 0;
        value++;
    }
    if (!strcasecmp(key, "name")) {
        if (pc_config_name_valid(value)) strcpy(c->name, value);
        else warn(c, line, "name: 1 to 40 characters, no quotes or backslashes");
    } else if (!strcasecmp(key, "language")) {
        if (!strcasecmp(value, "en") || !strcasecmp(value, "english")) c->language = PC_LANGUAGE_EN;
        else if (!strcasecmp(value, "de") || !strcasecmp(value, "deutsch") || !strcasecmp(value, "german")) c->language = PC_LANGUAGE_DE;
        else warn(c, line, "language: en or de");
    } else if (!strcasecmp(key, "delay")) {
        char *end = NULL;
        long ms = strtol(value, &end, 10);
        if (end != value && end && (!*end || !strcasecmp(end, "ms")) && ms >= PC_CONFIG_DELAY_MIN && ms <= PC_CONFIG_DELAY_MAX)
            c->delay_ms = (unsigned)ms;
        else warn(c, line, "delay: 100 to 500 (milliseconds)");
    } else if (!strcasecmp(key, "country")) {
        /* Two letters; "00" (the worldwide mode) is what this setting avoids. */
        if (strlen(value) == 2 && isalpha((unsigned char)value[0]) && isalpha((unsigned char)value[1])) {
            c->country[0] = (char)toupper((unsigned char)value[0]);
            c->country[1] = (char)toupper((unsigned char)value[1]);
            c->country[2] = 0;
        } else warn(c, line, "country: two letters, e.g. DE, AT, CH, GB, US");
    } else if (!strcasecmp(key, "maintenance")) {
        int on;
        if (!switch_value(value, &on)) c->maintenance = on;
        else warn(c, line, "maintenance: on or off");
    } else {
        warn(c, line, "unknown setting");
    }
}
static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) s[--n] = 0;
    return s;
}
void pc_config_parse(struct pc_config *c, const char *text, size_t size) {
    char buffer[256];
    unsigned line = 0;
    size_t i = 0;
    /* A byte order mark from Windows editors. */
    if (size >= 3 && !memcmp(text, "\xef\xbb\xbf", 3)) i = 3;
    while (i < size) {
        size_t start = i, n;
        while (i < size && text[i] != '\n') i++;
        n = i - start;
        i++;
        line++;
        if (n >= sizeof(buffer)) { warn(c, line, "line too long"); continue; }
        memcpy(buffer, text + start, n);
        buffer[n] = 0;
        if (memchr(buffer, 0, n)) { warn(c, line, "unreadable"); continue; }
        char *s = trim(buffer);
        if (!*s || *s == '#') continue;
        char *equals = strchr(s, '=');
        if (!equals) { warn(c, line, "expected key = value"); continue; }
        *equals = 0;
        char *value = equals + 1;
        /* A comment after a value, for every setting but the name. */
        char *key = trim(s);
        if (strcasecmp(key, "name")) {
            char *hash = strchr(value, '#');
            if (hash) *hash = 0;
        }
        apply(c, line, key, trim(value));
    }
}
void pc_config_load(struct pc_config *c, const char *path) {
    pc_config_defaults(c);
    if (!path) path = getenv("PICAST_CONFIG");
    if (!path) path = PC_CONFIG_PATH;
    FILE *f = fopen(path, "rb");
    if (f) {
        static char text[16384];
        size_t n = fread(text, 1, sizeof(text), f);
        fclose(f);
        pc_config_parse(c, text, n);
    }
    if (!strcmp(path, PC_CONFIG_PATH) && !access(PC_CONFIG_MAINTENANCE_FLAG, F_OK)) c->maintenance = 1;
}

/* The settings file, read once per process. */
static const struct pc_config *settings(void) {
    static struct pc_config c;
    static int loaded;
    if (!loaded) { pc_config_load(&c, NULL); loaded = 1; }
    return &c;
}
const char *pc_receiver_name(void) {
    const char *name = getenv("PICAST_NAME");
    return pc_config_name_valid(name) ? name : settings()->name;
}
enum pc_language pc_ui_language(void) {
    const char *forced = getenv("PICAST_LANGUAGE");
    if (forced) return !strcasecmp(forced, "de") ? PC_LANGUAGE_DE : PC_LANGUAGE_EN;
    return settings()->language;
}

static void json_string(const char *s) {
    putchar('"');
    for (; *s; s++) {
        unsigned char ch = (unsigned char)*s;
        if (ch == '"' || ch == '\\') printf("\\%c", ch);
        else if (ch < 0x20) printf("\\u%04x", ch);
        else putchar(ch);
    }
    putchar('"');
}
int pc_config_command(int argc, char **argv) {
    struct pc_config c;
    pc_config_load(&c, NULL);
    if (argc == 3 && !strcmp(argv[2], "maintenance")) return c.maintenance ? 0 : 1;
    if (argc == 3 && !strcmp(argv[2], "receiver")) return c.maintenance ? 1 : 0;
    if (argc != 2 && !(argc == 3 && !strcmp(argv[2], "show"))) return 2;
    printf("{\"name\":");
    json_string(c.name);
    printf(",\"language\":\"%s\",\"delay_ms\":%u,\"country\":\"%s\",\"maintenance\":%s,\"warnings\":[",
           c.language == PC_LANGUAGE_DE ? "de" : "en", c.delay_ms, c.country, c.maintenance ? "true" : "false");
    unsigned shown = c.warnings < 4 ? c.warnings : 4;
    for (unsigned i = 0; i < shown; i++) {
        if (i) putchar(',');
        json_string(c.warning[i]);
    }
    printf("]}\n");
    return 0;
}
