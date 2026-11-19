/* Guacamole client→server instruction handlers (src/libguac/user-handlers.c via
 * guac_user_handle_instruction): what every connected user sends once the handshake is done —
 * sync, mouse, touch, key, size, clipboard/file/pipe/argv/audio stream opens, blob (base64 decode),
 * ack, end, get/put objects, usb*, disconnect. Instructions are read from the input with
 * guac_parser_read exactly as the user input thread does (src/libguac/user-handshake.c), and each
 * is dispatched to a fresh user of a fresh client. The plugin-side handlers are stubs that accept
 * every stream and object, so the stream/object lifecycles in libguac run. The first byte picks the
 * socket read chunk size. */
#include "fuzz_common.h"
#include <guacamole/client.h>
#include <guacamole/parser.h>
#include <guacamole/protocol.h>
#include <guacamole/stream.h>
#include <guacamole/object.h>
#include <guacamole/user.h>

static volatile size_t sink;

static int h_mouse(guac_user* u, int x, int y, int m) { (void) u; sink += x + y + m; return 0; }
static int h_touch(guac_user* u, int id, int x, int y, int xr, int yr, double a, double f) {
    (void) u; sink += id + x + y + xr + yr + (int) a + (int) f; return 0; }
static int h_key(guac_user* u, int k, int p) { (void) u; sink += k + p; return 0; }
static int h_size(guac_user* u, int w, int h) { (void) u; sink += w + h; return 0; }
static int h_sync(guac_user* u, guac_timestamp t) { (void) u; sink += (size_t) t; return 0; }
static int h_stream(guac_user* u, guac_stream* s, char* mimetype) {
    (void) u; (void) s; sink += strlen(mimetype); return 0; }
static int h_named_stream(guac_user* u, guac_stream* s, char* mimetype, char* name) {
    (void) u; (void) s; sink += strlen(mimetype) + strlen(name); return 0; }
static int h_blob(guac_user* u, guac_stream* s, void* data, int length) {
    (void) u; (void) s;
    for (int i = 0; i < length; i++) sink += ((unsigned char*) data)[i];
    return 0;
}
static int h_ack(guac_user* u, guac_stream* s, char* error, guac_protocol_status status) {
    (void) u; (void) s; sink += strlen(error) + status; return 0; }
static int h_end(guac_user* u, guac_stream* s) { (void) u; (void) s; sink++; return 0; }
static int h_get(guac_user* u, guac_object* o, char* name) { (void) u; (void) o; sink += strlen(name); return 0; }
static int h_put(guac_user* u, guac_object* o, guac_stream* s, char* mimetype, char* name) {
    (void) u; (void) o; (void) s; sink += strlen(mimetype) + strlen(name); return 0; }
static int h_usbconnect(guac_user* u, const char* id, int vid, int pid, const char* dname,
        const char* serial, int dc, int dsc, int dp, const char* iface) {
    (void) u; sink += strlen(id) + vid + pid + strlen(dname) + strlen(serial) + dc + dsc + dp + strlen(iface);
    return 0;
}
static int h_usbdata(guac_user* u, const char* id, int ep, const char* data, const char* type) {
    (void) u; sink += strlen(id) + ep + strlen(data) + strlen(type); return 0; }
static int h_usbdisconnect(guac_user* u, const char* id) { (void) u; sink += strlen(id); return 0; }

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1)
        return 0;

    fuzz_mem_socket m = { data + 1, size - 1, 0, (size_t) (data[0] % 128) + 1 };
    guac_socket* in = fuzz_mem_socket_open(&m);
    guac_parser* parser = guac_parser_alloc();
    guac_client* client = guac_client_alloc();
    guac_user* user = guac_user_alloc();
    if (in == NULL || parser == NULL || client == NULL || user == NULL)
        goto done;

    user->client = client;
    user->socket = guac_socket_alloc();          /* replies are discarded */
    user->mouse_handler = h_mouse;
    user->touch_handler = h_touch;
    user->key_handler = h_key;
    user->size_handler = h_size;
    user->sync_handler = h_sync;
    user->clipboard_handler = h_stream;
    user->audio_handler = h_stream;
    user->file_handler = h_named_stream;
    user->pipe_handler = h_named_stream;
    user->argv_handler = h_named_stream;
    user->blob_handler = h_blob;
    user->ack_handler = h_ack;
    user->end_handler = h_end;
    user->get_handler = h_get;
    user->put_handler = h_put;
    user->usbconnect_handler = h_usbconnect;
    user->usbdata_handler = h_usbdata;
    user->usbdisconnect_handler = h_usbdisconnect;

    while (user->active && guac_parser_read(parser, in, 0) == 0)
        guac_user_handle_instruction(user, parser->opcode, parser->argc, parser->argv);

done:
    if (user != NULL) {
        if (user->socket != NULL) guac_socket_free(user->socket);
        user->socket = NULL;
        guac_user_free(user);
    }
    if (client != NULL) guac_client_free(client);
    if (parser != NULL) guac_parser_free(parser);
    if (in != NULL) guac_socket_free(in);
    return 0;
}
