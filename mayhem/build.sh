#!/usr/bin/env bash
#
# mayhem/build.sh — build guacamole-server's fuzz harnesses and its CUnit test suite.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. Two independent
# out-of-tree autotools builds, both under mayhem/ (gitignored by mayhem/.gitignore):
#   mayhem/build-fuzz  libguac, libguac_common, libguac_common_ssh, libguac-terminal,
#                      the serial plugin, guacd, guacenc and guaclog compiled with
#                      $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link (instrumented)
#   mayhem/build-test  the tree (plus the RDP and Kubernetes plugins) with the project's normal flags, plus `make check`'s
#                      test programs (built, not run) and the guaclog/guacenc tools that
#                      mayhem/test.sh drives as known-answer probes.
# Re-runnable: configure runs only when its tree has no Makefile; make is incremental.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Upstream ships configure.ac only; its generated files are gitignored, so (re)generate them
# whenever they are missing (a fresh or `git clean -ffdX`-ed tree).
[ -x configure ] && [ -f config.h.in ] || autoreconf -fi

# The fuzz tree is static and leaves out the protocol plugins no harness links (RDP, Kubernetes,
# and their FreeRDP/libwebsockets dependencies), so every harness links one sanitized archive set.
# The test tree enables RDP, libwebsockets and Kubernetes (FreeRDP 3 and libwebsockets are installed
# by mayhem/Dockerfile) so upstream's test_rdp and test_kubernetes suites are built too; it keeps
# shared libraries, because libtool refuses the RDP plugin modules' -shared link under
# --disable-shared. PulseAudio/Vorbis have no tests and stay off in both. -Wno-error: upstream
# builds with -Werror, which clang-19 trips on benign warnings (e.g. a missing newline at EOF in
# protocol.c).
FUZZ_CONF_OPTS=(--disable-shared --enable-static --without-rdp --without-pulse --without-websockets
                --disable-kubernetes --without-vorbis --disable-guacd-docker)
TEST_CONF_OPTS=(--with-rdp --with-websockets --enable-kubernetes --without-pulse --without-vorbis
                --disable-guacd-docker)

configure_tree() {   # <dir> <cflags> <ldflags> <configure options...>
    local dir="$1" cflags="$2" ldflags="$3"; shift 3
    mkdir -p "$dir"
    if [ ! -f "$dir/Makefile" ]; then
        (cd "$dir" && "$SRC/configure" "$@" CC="$CC" CFLAGS="$cflags" LDFLAGS="$ldflags")
    fi
}

# ---------------------------------------------------------------------------------------------
# 1) Sanitized, coverage-instrumented project build.
FUZZ="$SRC/mayhem/build-fuzz"
# Two UBSan checks are relaxed for the fuzz build (ASan and the rest of UBSan stay on and halting),
# because each fires on every ordinary input of several targets without any memory error:
#  - pointer-overflow: libguac_common's surface code computes `buffer + 0` on the NULL buffer of a
#    zero-sized surface (src/common/surface.c:998), on every terminal render;
#  - shift-base: `value << 6` in libguac's base64 decoder (src/libguac/protocol.c:1358) on every
#    blob longer than a few characters, and `alpha << 24` for every opaque fill
#    (src/common/surface.c:839) — left shifts into the sign bit of an int.
# shift-exponent, signed-integer-overflow and every other check remain enabled.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fno-sanitize=pointer-overflow,shift-base -fsanitize=fuzzer-no-link -O1 -Wno-error"
configure_tree "$FUZZ" "$FUZZ_CFLAGS" "$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" "${FUZZ_CONF_OPTS[@]}"
make -C "$FUZZ" -j"$MAYHEM_JOBS"

# ---------------------------------------------------------------------------------------------
# 2) Harnesses: each linked twice (libFuzzer + standalone reproducer).
H="$SRC/mayhem/harnesses"
B="$FUZZ/src"
OUT="$SRC/mayhem/bin"
mkdir -p "$OUT"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$FUZZ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ/standalone_main.o"

pc() { pkg-config "$@"; }
INC=(-include "$FUZZ/config.h" -I"$SRC/src/libguac" -I"$B/libguac")
LIBGUAC=("$B/libguac/.libs/libguac.a")
GUAC_DEPS=($(pc --libs cairo libpng libjpeg libwebp uuid openssl) -lpthread -lm)

objs_minus() {   # <dir> <prefix> <main-object>: a program's objects without its main()
    local d="$1" p="$2" m="$3"
    ls "$d"/"$p"-*.o | grep -v "/$m\$"
}

link_harness() { # <name> <harness.c> <extra args...>
    local name="$1" src="$2"; shift 2
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "${INC[@]}" -c "$src" -o "$FUZZ/$name.o" "${HCFLAGS[@]}"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$FUZZ/$name.o" "$@" "$FUZZ/lsan_off.o" -o "$OUT/$name"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$FUZZ/standalone_main.o" "$FUZZ/$name.o" "$@" "$FUZZ/lsan_off.o" -o "$OUT/$name-standalone"
}

HCFLAGS=()
link_harness fuzz_parser "$H/fuzz_parser.c" "${LIBGUAC[@]}" "${GUAC_DEPS[@]}"
link_harness fuzz_user_handlers "$H/fuzz_user_handlers.c" "${LIBGUAC[@]}" "${GUAC_DEPS[@]}"
HCFLAGS=($(pc --cflags cairo))
link_harness fuzz_display "$H/fuzz_display.c" "${LIBGUAC[@]}" "${GUAC_DEPS[@]}"

HCFLAGS=(-I"$SRC/src/guaclog")
link_harness fuzz_guaclog "$H/fuzz_guaclog.c" $(objs_minus "$B/guaclog" guaclog guaclog-guaclog.o) \
    "${LIBGUAC[@]}" "${GUAC_DEPS[@]}"

HCFLAGS=(-I"$SRC/src/guacenc" $(pc --cflags libavcodec libavformat libavutil libswscale))
link_harness fuzz_guacenc "$H/fuzz_guacenc.c" $(objs_minus "$B/guacenc" guacenc guacenc-guacenc.o) \
    "${LIBGUAC[@]}" $(pc --libs libavcodec libavformat libavutil libswscale) "${GUAC_DEPS[@]}"

HCFLAGS=(-I"$SRC/src/guacd")
link_harness fuzz_guacd_conf "$H/fuzz_guacd_conf.c" "$B/guacd/guacd-conf-file.o" "$B/guacd/guacd-conf-parse.o" \
    "${LIBGUAC[@]}" "${GUAC_DEPS[@]}"

TERM_LIBS=("$B/terminal/.libs/libguac-terminal.a" "$B/common/.libs/libguac_common.a" "${LIBGUAC[@]}"
           $(pc --libs pangocairo pango cairo) "${GUAC_DEPS[@]}")
HCFLAGS=(-I"$SRC/src/terminal" $(pc --cflags pangocairo))
link_harness fuzz_terminal "$H/fuzz_terminal.c" "${TERM_LIBS[@]}"
link_harness fuzz_color_scheme "$H/fuzz_color_scheme.c" "${TERM_LIBS[@]}"

HCFLAGS=(-I"$SRC/src/common-ssh" $(pc --cflags libssh2))
link_harness fuzz_ssh_key "$H/fuzz_ssh_key.c" "$B/common-ssh/.libs/libguac_common_ssh.a" \
    "$B/common/.libs/libguac_common.a" "${LIBGUAC[@]}" $(pc --libs libssh2) "${GUAC_DEPS[@]}"
HCFLAGS=(-I"$SRC/src/common-ssh" -I"$SRC/src/common" $(pc --cflags libssh2))
# fuzz_sftp_path compiles src/common-ssh/sftp.c into the harness (its name handlers are static),
# so the archive's own sftp.o is not pulled in.
link_harness fuzz_sftp_path "$H/fuzz_sftp_path.c" "$B/common-ssh/.libs/libguac_common_ssh.a" \
    "$B/common/.libs/libguac_common.a" "${LIBGUAC[@]}" $(pc --libs libssh2) "${GUAC_DEPS[@]}"

# ---------------------------------------------------------------------------------------------
# 3) The test suite and the known-answer tools, with the project's normal flags.
TEST="$SRC/mayhem/build-test"
configure_tree "$TEST" "-O2 -Wno-error $COVERAGE_FLAGS" "$COVERAGE_FLAGS" "${TEST_CONF_OPTS[@]}"
make -C "$TEST" -j"$MAYHEM_JOBS"
# Build the CUnit test programs without running them (mayhem/test.sh runs them). A runner left
# empty by an interrupted earlier run would otherwise look up to date.
find "$TEST" -name _generated_runner.c -empty -delete
GUAC_TEST_BUILD="$TEST" make -C "$TEST" -j"$MAYHEM_JOBS" check TESTS= \
    GEN_RUNNER="sh $SRC/mayhem/gen-test-runner.sh"
