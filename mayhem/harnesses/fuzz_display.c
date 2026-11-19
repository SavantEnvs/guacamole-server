/* Display engine (src/libguac/display*.c): what every protocol plugin (RDP, VNC, terminal) drives
 * to turn remote-desktop drawing into Guacamole protocol — layers and off-screen buffers, resize,
 * move/stack/reparent/opacity, raw and Cairo drawing, external (plugin-owned) buffers that may be
 * replaced by NULL, the cursor, and frame completion: dirty-rect planning, copy/scroll search,
 * rect combining, and the PNG/JPEG/WebP encode workers (display-plan*.c, display-flush.c,
 * display-worker.c). The input is a byte-coded sequence of these public API calls on a fresh
 * display; the encoded output goes to the client's (user-less, discarding) broadcast socket.
 * Sizes are bounded to 256x256 so frames stay cheap; the 704fdc4875 fix (an infinite loop in
 * guac_display_frame_complete() for layers whose buffer was replaced by NULL) is reachable. */
#include "fuzz_common.h"
#include <cairo/cairo.h>
#include <guacamole/client.h>
#include <guacamole/display.h>
#include <guacamole/mem.h>
#include <guacamole/rect.h>

#define MAX_LAYERS 8
#define MAX_EXT 64
#define MAX_DIM 256

typedef struct reader { const uint8_t* p; size_t n; } reader;

static int rd(reader* r) {   /* next byte, or -1 at end of input */
    if (r->n == 0) return -1;
    r->n--; return *(r->p++);
}
static int rd_or0(reader* r) { int v = rd(r); return v < 0 ? 0 : v; }
static int rd_dim(reader* r) { return (rd_or0(r) | (rd_or0(r) << 8)) % (MAX_DIM + 1); }
static int rd_coord(reader* r) { return (int) (int16_t) (rd_or0(r) | (rd_or0(r) << 8)) % 512; }

static void rd_rect(reader* r, guac_display_layer_raw_context* ctx, guac_rect* out) {
    int x = rd_dim(r), y = rd_dim(r), w = rd_dim(r), h = rd_dim(r);
    guac_rect_init(out, x, y, w, h);
    guac_rect_constrain(out, &ctx->bounds);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    reader r = { data, size };
    guac_client* client = guac_client_alloc();
    if (client == NULL)
        return 0;
    guac_display* display = guac_display_alloc(client);
    if (display == NULL) { guac_client_free(client); return 0; }

    guac_display_layer* layers[MAX_LAYERS] = { guac_display_default_layer(display) };
    int parent_of[MAX_LAYERS] = { -1 };   /* slot index of each layer's parent, -1 = none */
    int external[MAX_LAYERS] = { 0 };     /* slot's buffer is plugin-owned (or detached) */
    int nlayers = 1;
    void* ext[MAX_EXT];
    int next = 0;

    int op;
    while ((op = rd(&r)) >= 0) {
        int li = rd_or0(&r) % nlayers;
        guac_display_layer* l = layers[li];
        switch (op % 16) {
            case 0: case 1:
                if (nlayers < MAX_LAYERS) {
                    parent_of[nlayers] = -1;
                    external[nlayers] = 0;
                    layers[nlayers++] = (op % 16 == 0)
                        ? guac_display_alloc_layer(display, rd_or0(&r) & 1)
                        : guac_display_alloc_buffer(display, rd_or0(&r) & 1);
                }
                break;
            case 2: {  /* free the most recently allocated layer, unless it is still a parent (a
                        * plugin frees children before their parent) */
                int in_use = 0;
                for (int i = 0; i < nlayers - 1; i++)
                    in_use |= parent_of[i] == nlayers - 1;
                if (nlayers > 1 && !in_use)
                    guac_display_free_layer(layers[--nlayers]);
                break;
            }
            case 3: {
                /* Any size, 0x0 included: plugins pass the remote's desktop/cursor size straight
                 * through (vnc.c, rdp/pointer.c) and display.h documents only an upper clamp. */
                int w = rd_dim(&r), h = rd_dim(&r);
                /* guac_display_layer_resize() does not resize a plugin-owned buffer (display.h:
                 * "that buffer must instead be manually maintained by the caller"), so such a
                 * layer is only resized by handing it a new buffer (op 11). */
                if (!external[li])
                    guac_display_layer_resize(l, w, h);
                break;
            }
            case 4: { int x = rd_coord(&r), y = rd_coord(&r); guac_display_layer_move(l, x, y); break; }
            case 5: guac_display_layer_stack(l, (int8_t) rd_or0(&r)); break;
            case 6: {
                int pi = rd_or0(&r) % nlayers;
                if (li != 0 && pi != li) {
                    parent_of[li] = pi;
                    guac_display_layer_set_parent(l, layers[pi]);
                }
                break;
            }
            case 7: guac_display_layer_set_opacity(l, rd_or0(&r)); break;
            case 8: guac_display_layer_set_lossless(l, rd_or0(&r) & 1); break;
            case 9: case 10: case 11: {
                guac_display_layer_raw_context* ctx = guac_display_layer_open_raw(l);
                int kind = op % 16;
                if (kind == 11) {
                    external[li] = 1;
                    /* Hand the layer a plugin-owned buffer, or detach it (NULL), as RDP does
                     * with its GDI surface. */
                    if (rd_or0(&r) & 1 || next == MAX_EXT) {
                        ctx->buffer = NULL;
                    }
                    else {
                        int w = rd_dim(&r) + 1, h = rd_dim(&r) + 1;
                        void* buf = calloc((size_t) w * h, 4);
                        if (buf != NULL) {
                            ext[next++] = buf;
                            ctx->buffer = buf;
                            ctx->stride = (size_t) w * 4;
                            guac_rect_init(&ctx->bounds, 0, 0, w, h);
                        }
                    }
                }
                else if (ctx->buffer != NULL) {
                    guac_rect dst;
                    rd_rect(&r, ctx, &dst);
                    if (kind == 9) {
                        uint32_t color = (uint32_t) rd_or0(&r) << 24 | (uint32_t) rd_or0(&r) << 16
                                       | (uint32_t) rd_or0(&r) << 8 | (uint32_t) rd_or0(&r);
                        guac_display_layer_raw_context_set(ctx, &dst, color);
                    }
                    else {
                        size_t need = (size_t) guac_rect_width(&dst) * guac_rect_height(&dst) * 4;
                        if (!guac_rect_is_empty(&dst) && need <= r.n) {
                            guac_display_layer_raw_context_put(ctx, &dst, r.p,
                                    (size_t) guac_rect_width(&dst) * 4);
                            r.p += need; r.n -= need;
                        }
                    }
                    guac_rect_extend(&ctx->dirty, &dst);
                    if (rd_or0(&r) & 1)
                        ctx->hint_from = layers[rd_or0(&r) % nlayers];
                }
                guac_display_layer_close_raw(l, ctx);
                break;
            }
            case 12: {
                /* Cairo drawing is only allowed on a layer that still has a buffer. */
                guac_display_layer_raw_context* ctx = guac_display_layer_open_raw(l);
                int has_buffer = ctx->buffer != NULL;
                guac_display_layer_close_raw(l, ctx);
                if (has_buffer) {
                    guac_display_layer_cairo_context* c = guac_display_layer_open_cairo(l);
                    int x = rd_dim(&r), y = rd_dim(&r), w = rd_dim(&r), h = rd_dim(&r);
                    cairo_set_source_rgba(c->cairo, rd_or0(&r) / 255.0, rd_or0(&r) / 255.0,
                            rd_or0(&r) / 255.0, rd_or0(&r) / 255.0);
                    cairo_rectangle(c->cairo, x, y, w, h);
                    cairo_fill(c->cairo);
                    guac_rect d; guac_rect_init(&d, x, y, w, h);
                    guac_rect_extend(&c->dirty, &d);
                    guac_display_layer_close_cairo(l, c);
                }
                break;
            }
            case 13: guac_display_set_cursor(display, (guac_display_cursor_type) (rd_or0(&r) % 4)); break;
            case 14: guac_display_end_frame(display); break;
            case 15: guac_display_end_multiple_frames(display, rd_or0(&r) % 4); break;
        }
    }
    guac_display_end_frame(display);

    guac_display_free(display);
    guac_client_free(client);
    for (int i = 0; i < next; i++)
        free(ext[i]);
    return 0;
}
