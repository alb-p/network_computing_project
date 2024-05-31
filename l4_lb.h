#ifndef HHD_V1_H_
#define HHD_V1_H_

#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <assert.h>

#include <cyaml/cyaml.h>
#include <sys/types.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>

#include "log.h"

// Include skeleton file
#include "l4_lb.skel.h"

static __u32 xdp_flags = 0;

struct root {
    const char *vip;
    struct backend *backends;
    uint64_t backends_count;
};

struct backend {
    const char *ip;
};

static const cyaml_schema_field_t backend_field_schema[] = {
    CYAML_FIELD_STRING_PTR("ip", CYAML_FLAG_POINTER, struct backend, ip, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t backend_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct backend, backend_field_schema),
};
////////////////
static const cyaml_schema_field_t root_field_schema[] = {
    CYAML_FIELD_STRING_PTR("vip", CYAML_FLAG_POINTER, struct root, vip, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE("backends", CYAML_FLAG_POINTER, struct root, backends, &backend_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END
};

static const cyaml_schema_value_t root_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct root, root_field_schema),
};

static const cyaml_config_t config = {
	.log_fn = cyaml_log,            /* Use the default logging function. */
	.mem_fn = cyaml_mem,            /* Use the default memory allocator. */
	.log_level = CYAML_LOG_WARNING, /* Logging errors and warnings only. */
};

#endif //HHD_V1_H_