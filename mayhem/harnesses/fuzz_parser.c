/* Guacamole protocol instruction parser (src/libguac/parser.c, guac_parser_read): the framing
 * every network client connection, guacd and the recording tools go through. The first input byte
 * picks the read chunk size, so instructions are split across socket reads (exercising the
 * parser's partial-element and buffer-shift paths); the rest is the instruction stream. Each
 * complete instruction's opcode and arguments are read until EOF or a parse error. */
#include "fuzz_common.h"
#include <guacamole/parser.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1)
        return 0;

    fuzz_mem_socket m = { data + 1, size - 1, 0, (size_t) (data[0] % 128) + 1 };
    guac_socket* socket = fuzz_mem_socket_open(&m);
    guac_parser* parser = guac_parser_alloc();
    if (socket == NULL || parser == NULL)
        goto done;

    while (guac_parser_read(parser, socket, 0) == 0) {
        volatile size_t total = strlen(parser->opcode);
        for (int i = 0; i < parser->argc; i++)
            total += strlen(parser->argv[i]);
        (void) total;
    }

done:
    if (parser != NULL) guac_parser_free(parser);
    if (socket != NULL) guac_socket_free(socket);
    return 0;
}
