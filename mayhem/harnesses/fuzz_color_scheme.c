/* Terminal color scheme parser (src/terminal/color-scheme.c, xparsecolor.c, named-colors.c):
 * the `color-scheme` connection parameter of SSH/telnet/serial/Kubernetes connections —
 * "foreground: rgb:ff/ff/ff; background: black; color9: ..." with X11 color names and
 * rgb:/# specs. The input is the parameter value. */
#include "fuzz_common.h"
#include <guacamole/client.h>
#include "terminal/color-scheme.h"
#include "terminal/palette.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char* scheme = malloc(size + 1);
    if (scheme == NULL)
        return 0;
    memcpy(scheme, data, size);
    scheme[size] = '\0';

    guac_client* client = guac_client_alloc();
    if (client != NULL) {
        guac_terminal_color fg, bg;
        guac_terminal_color palette[256];
        guac_terminal_parse_color_scheme(client, scheme, &fg, &bg, &palette);
        guac_client_free(client);
    }
    free(scheme);
    return 0;
}
