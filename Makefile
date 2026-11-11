# PiCast: build on Raspberry Pi OS (or any Debian-based arm64/x86-64 Linux).
#   make            receiver (build/picast) and battery service (build/picast-power)
#   make test       all unit tests
#   make sanitize   the same tests with AddressSanitizer and UBSan
# Packages: see BUILD_PACKAGES in tools/picast-setup.sh.
CC ?= cc
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
CFLAGS ?= -O2 -g
override CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS += -Iinclude -Ithird_party/playfair -D_GNU_SOURCE -D_DEFAULT_SOURCE
PACKAGES = openssl libplist-2.0 gstreamer-app-1.0 gstreamer-video-1.0 cairo libdrm
CPPFLAGS += $(shell pkg-config --cflags $(PACKAGES))
LDLIBS += $(shell pkg-config --libs $(PACKAGES)) -lpthread -lm

SOURCES = $(filter-out src/main.c src/power_main.c,$(wildcard src/*.c))
OBJECTS = $(SOURCES:src/%.c=build/obj/%.o)
# PlayFair (GPL-3.0, third_party/playfair) unwraps the media key; upstream code
# needs wrapping signed arithmetic and no strict aliasing.
PLAYFAIR = $(patsubst third_party/playfair/%.c,build/playfair/%.o,$(wildcard third_party/playfair/*.c))
LIBRARY = build/libpicast.a

.PHONY: all test sanitize clean
all: build/picast build/picast-power

build/obj/%.o: src/%.c $(wildcard include/*.h) | build/obj
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/playfair/%.o: third_party/playfair/%.c | build/playfair
	$(CC) -O2 -g -std=c11 -fwrapv -fno-strict-aliasing $(PLAYFAIR_SANITIZE) -Ithird_party/playfair -c $< -o $@
$(LIBRARY): $(OBJECTS) $(PLAYFAIR)
	rm -f $@
	$(AR) rcs $@ $^
build/obj build/playfair:
	mkdir -p $@

build/picast: src/main.c $(LIBRARY)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DPICAST_VERSION='"$(VERSION)"' $< $(LIBRARY) $(LDFLAGS) $(LDLIBS) -o $@
build/picast-power: src/power_main.c $(LIBRARY)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LIBRARY) $(LDFLAGS) $(LDLIBS) -o $@

# --- tests --------------------------------------------------------------------
# Each test is one driver linked against the library; nothing touches a radio.
TESTS = protocol pair native_tcp srp pin pin_control fairplay mirror_crypto session fp_key \
        clock playout trace battery guard crop config
build/test_protocol: tests/test_protocol.c tests/test_data.c tests/test_schedule.c tests/test_rtsp.c tests/test_mirror.c $(LIBRARY)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LIBRARY) $(LDFLAGS) $(LDLIBS) -o $@
build/test_pair: tests/test_pair.c $(LIBRARY)
build/test_native_tcp: tests/test_native_tcp.c $(LIBRARY)
build/test_srp: tests/srp_driver.c $(LIBRARY)
build/test_pin: tests/pin_driver.c $(LIBRARY)
build/test_pin_control: tests/pin_control_driver.c $(LIBRARY)
build/test_fairplay: tests/test_fairplay.c $(LIBRARY)
build/test_mirror_crypto: tests/mirror_crypto_driver.c $(LIBRARY)
build/test_session: tests/session_driver.c $(LIBRARY)
build/test_fp_key: tests/test_fp_key.c $(LIBRARY)
build/test_media_namespace: tests/media_namespace_driver.c $(LIBRARY)
build/test_clock: tests/clock_driver.c $(LIBRARY)
build/test_playout: tests/playout_driver.c $(LIBRARY)
build/test_trace: tests/trace_driver.c $(LIBRARY)
build/test_battery: tests/battery_driver.c $(LIBRARY)
build/test_guard: tests/guard_driver.c $(LIBRARY)
build/test_crop: tests/crop_driver.c $(LIBRARY)
build/test_config: tests/config_driver.c $(LIBRARY)
build/test_%:
	$(CC) $(CPPFLAGS) $(CFLAGS) $(firstword $^) $(LIBRARY) $(LDFLAGS) $(LDLIBS) -o $@
# Radio queries with every netlink call intercepted by the test (link-time
# wrapping; the sanitizers intercept the same calls, so `make sanitize` skips it).
WRAPPED_TESTS ?= 1
build/test_firmware_awake: tests/firmware_awake_driver.c $(LIBRARY)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(firstword $^) $(LIBRARY) -Wl,--wrap=socket,--wrap=bind,--wrap=close,--wrap=if_nametoindex,--wrap=poll,--wrap=sendto,--wrap=recvfrom $(LDFLAGS) $(LDLIBS) -o $@

test: build/picast build/picast-power $(TESTS:%=build/test_%) build/test_firmware_awake
	./build/test_protocol
	./build/test_pair
	python3 tests/verify_info.py ./build/test_pair
	./build/test_native_tcp
	python3 tests/verify_srp.py ./build/test_srp
	python3 tests/verify_pin.py ./build/test_pin
	python3 tests/verify_pin.py ./build/test_pin_control
	./build/test_fairplay
	python3 tests/verify_mirror_crypto.py ./build/test_mirror_crypto
	python3 tests/verify_session.py ./build/test_session
	./build/test_fp_key
	./build/test_clock
	./build/test_playout
	./build/test_trace
	./build/test_battery
	./build/test_guard
	./build/test_crop
	./build/test_config
	if [ "$(WRAPPED_TESTS)" = 1 ]; then ./build/test_firmware_awake; fi
	python3 -m unittest discover -s tests -p 'test_*.py'
	./build/picast version

# Needs root: two private network namespaces, no change to the host's networking.
.PHONY: namespace-test
namespace-test: build/test_media_namespace
	./build/test_media_namespace

sanitize:
	$(MAKE) clean
	$(MAKE) test WRAPPED_TESTS=0 CFLAGS='-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer' \
		LDFLAGS='-fsanitize=address,undefined' PLAYFAIR_SANITIZE='-fsanitize=address,undefined'

clean:
	rm -rf build
