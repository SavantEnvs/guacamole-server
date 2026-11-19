/* guacenc (src/guacenc/encode.c): `guacenc -f -s 160x120 <recording>`, which replays a Guacamole
 * session recording (drawing instructions, base64 PNG/JPEG/WebP image streams, layers, buffers,
 * cursor) and encodes it to MPEG-4 video. The input is the recording file; the video goes to a
 * scratch file under $TMPDIR. Both files are removed after every input. A small video size keeps
 * per-frame encoding cheap; the recording's own display size is independent of it. */
#include "fuzz_common.h"
#include <stdbool.h>
#include "guacenc.h"
#include "encode.h"
#include "log.h"

/* guacenc decodes JPEG blobs with libjpeg's default error manager, whose error_exit() calls
 * exit() on a malformed image (src/guacenc/jpeg.c). An exit() during an input is lifted to
 * abort() so it is reported as a crash with a backtrace rather than a silent process exit
 * The handler is registered on the first input, after libFuzzer's own exit callback, so that it
 * runs first (atexit handlers run in reverse order of registration). */
static volatile int in_input;
static void abort_if_in_input(void) { if (in_input) abort(); }

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char in_path[4096], out_path[4200];
    static int registered;
    if (!registered) { atexit(abort_if_in_input); registered = 1; }
    guacenc_log_level = GUAC_LOG_ERROR - 1;   /* silence logging (same value for every input) */

    int fd = fuzz_write_tmp(data, size, in_path, sizeof(in_path));
    if (fd < 0)
        return 0;
    close(fd);
    snprintf(out_path, sizeof(out_path), "%s.m4v", in_path);

    in_input = 1;
    guacenc_encode(in_path, out_path, "mpeg4", 160, 120, 2000000, true);
    in_input = 0;

    unlink(out_path);
    unlink(in_path);
    return 0;
}
