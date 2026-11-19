/* SSH private-key intake (src/common-ssh/key.c, guac_common_ssh_key_alloc), fed by the
 * `private-key` and `passphrase` connection parameters of SSH and SFTP connections. This is NOT a
 * key parser: guac only runs is_passphrase_needed() (guac_strnstr for "ENCRYPTED", then strncmp of
 * the OpenSSH v1 header and its base64 "unencrypted" prefix) and memcpy()s the key;
 * libssh2 parses it later, at authentication. The reachable code is that heuristic plus the copy,
 * which is why coverage stays at a few dozen edges. Input: first byte = passphrase length
 * (0 = none), then the passphrase, then the key text. */
#include "fuzz_common.h"
#include "common-ssh/key.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1)
        return 0;
    size_t plen = data[0];
    data++; size--;
    if (plen > size)
        plen = size;

    char* pass = NULL;
    if (plen > 0) {
        pass = malloc(plen + 1);
        if (pass == NULL) return 0;
        memcpy(pass, data, plen);
        pass[plen] = '\0';
    }
    size_t klen = size - plen;
    char* key = malloc(klen + 1);
    if (key == NULL) { free(pass); return 0; }
    memcpy(key, data + plen, klen);
    key[klen] = '\0';

    guac_common_ssh_key* k = guac_common_ssh_key_alloc(key, (int) klen, pass);
    if (k != NULL)
        guac_common_ssh_key_free(k);

    free(key);
    free(pass);
    return 0;
}
