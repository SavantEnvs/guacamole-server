/* Terminal emulator (src/terminal: terminal.c, terminal-handlers.c, buffer.c, display.c): the
 * bytes an SSH/telnet/serial/Kubernetes server sends are written to guac_terminal_write(), which
 * runs the VT100/xterm state machine — C0/C1 controls, ESC, CSI (SGR, cursor, scroll regions,
 * modes), OSC (title, colors, palette, download/upload/pipe redirection), DCS/APC — and the frame
 * is then rendered through libguac's display engine. A fresh 640x400 terminal per input, driven
 * through the lifecycle the SSH/telnet plugins use: create, start, write, then stop the client so
 * the render thread flushes the final state once and exits, and free (which joins it). */
#include "fuzz_common.h"
#include <guacamole/client.h>
#include <guacamole/mem.h>
#include "terminal/terminal.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    guac_client* client = guac_client_alloc();
    if (client == NULL)
        return 0;
    client->log_handler = NULL;

    guac_terminal_options* options = guac_terminal_options_create(640, 400, 96);
    guac_terminal* term = guac_terminal_create(client, options);
    if (term != NULL) {
        guac_terminal_start(term);
        guac_terminal_write(term, (const char*) data, (int) size);
        guac_client_stop(client);
        guac_terminal_notify(term);   /* wake the render thread if it is idle-waiting */
        guac_terminal_free(term);
    }
    guac_mem_free(options);
    guac_client_free(client);
    return 0;
}
