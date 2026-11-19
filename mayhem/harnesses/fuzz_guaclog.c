/* guaclog (src/guaclog/interpret.c): `guaclog -f <recording>`, which interprets the key events of
 * a Guacamole session recording into human-readable text. The input is the recording file; the
 * text output goes to a scratch file under $TMPDIR. Both files are removed after every input. */
#include "fuzz_common.h"
#include <stdbool.h>
#include "guaclog.h"
#include "interpret.h"
#include "log.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char in_path[4096], out_path[4200];
    guaclog_log_level = GUAC_LOG_ERROR - 1;   /* silence logging (same value for every input) */

    int fd = fuzz_write_tmp(data, size, in_path, sizeof(in_path));
    if (fd < 0)
        return 0;
    close(fd);
    snprintf(out_path, sizeof(out_path), "%s.txt", in_path);

    guaclog_interpret(in_path, out_path, true);

    unlink(out_path);
    unlink(in_path);
    return 0;
}
