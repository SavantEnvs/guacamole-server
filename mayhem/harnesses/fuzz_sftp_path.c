/* SFTP filename handling (src/common-ssh/sftp.c), the path the SSH/RDP/VNC SFTP filesystem
 * takes for names a connected client sends:
 *   - `get`/`put` object stream names -> guac_common_ssh_sftp_translate_name(), which runs
 *     guac_common_ssh_sftp_normalize_path() (fixed-size path_scratch / path_components[] stack
 *     buffers) and then guac_ssh_append_path() onto the filesystem root;
 *   - `file` stream filenames -> guac_ssh_append_filename() onto the upload directory, as
 *     guac_common_ssh_sftp_handle_file_stream() does before opening the remote file.
 * translate_name and append_filename are static, so sftp.c is compiled into this harness (the
 * archive's sftp.o is then not linked). No SSH session is needed: these run before any libssh2 call.
 * Input: the client-supplied name (NUL-terminated copy; protocol strings are NUL-terminated). */
#include "fuzz_common.h"
#include "../../src/common-ssh/sftp.c"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char* name = malloc(size + 1);
    if (name == NULL)
        return 0;
    memcpy(name, data, size);
    name[size] = '\0';

    /* root_path / upload_path come from connection parameters (sftp-root-directory,
     * sftp-directory), not from the client; fixed values here. */
    guac_common_ssh_sftp_filesystem fs;
    memset(&fs, 0, sizeof(fs));
    guac_strlcpy(fs.root_path, "/home/guac", sizeof(fs.root_path));
    guac_strlcpy(fs.upload_path, "/home/guac/upload", sizeof(fs.upload_path));
    guac_object object;
    memset(&object, 0, sizeof(object));
    object.data = &fs;

    char fullpath[GUAC_COMMON_SSH_SFTP_MAX_PATH];
    guac_common_ssh_sftp_translate_name(fullpath, &object, name);
    guac_ssh_append_filename(fullpath, fs.upload_path, name);

    free(name);
    return 0;
}
