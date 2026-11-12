/* Settings file: defaults, every setting, and what is ignored. */
#include "picast_config.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void parse(struct pc_config *c, const char *text) {
    pc_config_defaults(c);
    pc_config_parse(c, text, strlen(text));
}
int main(void) {
    struct pc_config c;
    parse(&c, "");
    assert(!strcmp(c.name, "PiCast") && c.language == PC_LANGUAGE_EN && c.delay_ms == 270 && !c.maintenance && !c.warnings);
    /* Every setting, with spaces, comments, Windows line ends and a byte order mark. */
    parse(&c, "\xef\xbb\xbf# PiCast\r\nname = Wohnzimmer-TV\r\n  language=de  \r\ndelay = 320 # smoother\r\nmaintenance = on\r\n");
    assert(!strcmp(c.name, "Wohnzimmer-TV") && c.language == PC_LANGUAGE_DE && c.delay_ms == 320 && c.maintenance && !c.warnings);
    /* Names: UTF-8, a hash and quotes to keep spaces; nothing the menu cannot show. */
    parse(&c, "name = Küche # 2\n");
    assert(!strcmp(c.name, "Küche # 2"));
    parse(&c, "name = \"  Jan's TV \"\n");
    assert(!strcmp(c.name, "  Jan's TV "));
    const char *bad[] = {"name =\n", "name = \"\"\n", "name =    \n", "name = a\\b\n", "name = \xc3\x28\n",
                         "name = \xed\xa0\x80\n", "name = 12345678901234567890123456789012345678901\n", "name = a\"b\n"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        parse(&c, bad[i]);
        assert(!strcmp(c.name, "PiCast") && c.warnings == 1);
    }
    assert(pc_config_name_valid("1234567890123456789012345678901234567890"));
    /* Out of range or unknown: default kept, one warning each. */
    parse(&c, "delay = 99\ndelay = 501\ndelay = fast\nlanguage = fr\nmaintenance = maybe\ncolour = blue\nno equals sign\n");
    assert(c.delay_ms == 270 && c.language == PC_LANGUAGE_EN && !c.maintenance && c.warnings == 7);
    assert(!strncmp(c.warning[0], "line 1: delay", 13));
    parse(&c, "delay = 100ms\nmaintenance = Yes\nLANGUAGE = Deutsch\n");
    assert(c.delay_ms == 100 && c.maintenance && c.language == PC_LANGUAGE_DE && !c.warnings);
    parse(&c, "");
    assert(!strcmp(c.country, "DE"));
    parse(&c, "country = at # Austria\n");
    assert(!strcmp(c.country, "AT") && !c.warnings);
    parse(&c, "country = 00\ncountry = DEU\ncountry =\n");
    assert(!strcmp(c.country, "DE") && c.warnings == 3 && !strncmp(c.warning[0], "line 1: country", 15));
    parse(&c, "maintenance = off\n");
    assert(!c.maintenance);
    /* The file itself: missing means defaults; the receiver name follows it. */
    pc_config_load(&c, "/nonexistent/picast.txt");
    assert(!strcmp(c.name, "PiCast") && !c.maintenance);
    char path[] = "/tmp/picast-config-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "w");
    fputs("name = Beamer\nlanguage = de\n", f);
    fclose(f);
    setenv("PICAST_CONFIG", path, 1);
    assert(!strcmp(pc_receiver_name(), "Beamer") && pc_ui_language() == PC_LANGUAGE_DE);
    setenv("PICAST_NAME", "Override", 1);
    setenv("PICAST_LANGUAGE", "en", 1);
    assert(!strcmp(pc_receiver_name(), "Override") && pc_ui_language() == PC_LANGUAGE_EN);
    unlink(path);
    puts("config: defaults, settings, names and invalid lines passed");
    return 0;
}
