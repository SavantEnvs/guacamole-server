/* guacd configuration file parser (src/guacd/conf-file.c + conf-parse.c): guacd_conf_parse_file(),
 * which guacd runs on /etc/guacamole/guacd.conf — sections, parameters, quoted values, comments,
 * log levels. The input is the file contents. */
#include "fuzz_common.h"
#include <guacamole/mem.h>
#include "conf.h"
#include "conf-file.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char path[4096];
    int fd = fuzz_write_tmp(data, size, path, sizeof(path));
    if (fd < 0)
        return 0;
    unlink(path);

    guacd_config* conf = guac_mem_zalloc(sizeof(guacd_config));
    guacd_conf_parse_file(conf, fd);
    close(fd);

    guac_mem_free(conf->bind_host);
    guac_mem_free(conf->bind_port);
    guac_mem_free(conf->pidfile);
#ifdef ENABLE_SSL
    guac_mem_free(conf->cert_file);
    guac_mem_free(conf->key_file);
#endif
    guac_mem_free(conf);
    return 0;
}
