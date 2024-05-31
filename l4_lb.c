// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <argparse.h>
#include <net/if.h>

#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <signal.h>

#include "log.h"
#include "l4_lb.h"

struct load_s {
   __u64 packets_rcvd;
   __u64 flows;
   __u64 load;
};

struct flow_t {
   __u32 IPsrc;
   __u32 IPdst;
   __u16 srcPort;
   __u16 dstPort;
   __u8  protocol;

};

int load_maps_config(const char *config_file, struct l4_lb_bpf *skel) {
    struct root *root;
    cyaml_err_t err;
    int ret = EXIT_SUCCESS;

    /* Load input file. */
	err = cyaml_load_file(config_file, &config, &root_schema, (void **) &root, NULL);
	if (err != CYAML_OK) {
		fprintf(stderr, "ERROR: %s\n", cyaml_strerror(err));
		return EXIT_FAILURE;
	}

    log_info("Loaded %d IPs", root->backends_count);

    // Get file descriptor of the map
    int load_map_fd = bpf_map__fd(skel->maps.load);
    int flow_backend_map_fd = bpf_map__fd(skel->maps.flow_backend);
    int utils_map_fd = bpf_map__fd(skel->maps.utils);

    // Check if the file descriptor is valid
    if (load_map_fd < 0 || flow_backend_map_fd < 0 || utils_map_fd < 0) {
        log_error("Failed to get file descriptor of BPF maps: %s", strerror(errno));
        ret = EXIT_FAILURE;
        goto cleanup_yaml;
    }

    /* Load the IPs in the BPF map */
    for (int i = 0; i < root->backends_count; i++) {
        log_info("Loading IP %s", root->backends[i].ip);

        // Convert the IP to an integer
        struct in_addr addr;
        int ret = inet_pton(AF_INET, root->backends[i].ip, &addr);
        if (ret != 1) {
            log_error("Failed to convert IP %s to integer", root->backends[i].ip);
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        // Now write the IP to the BPF map
        struct map_value_t value = {
            .threshold = ips->ips[i].threshold,
            .packets_rcvd = 0,
        };

        ret = bpf_map_update_elem(threshold_map_fd, &addr.s_addr, &value, BPF_ANY);
        if (ret != 0) {
            log_error("Failed to update BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            goto cleanup_yaml;  
        }        
    }

    // Get fd of port map
    int port_map_fd = bpf_map__fd(skel->maps.ip_to_port);

    // Check if the file descriptor is valid
    if (port_map_fd < 0) {
        log_error("Failed to get file descriptor of BPF map: %s", strerror(errno));
        ret = EXIT_FAILURE;
        goto cleanup_yaml;
    }

    /* Load the IPs in the BPF map */
    for (int i = 0; i < ips->ips_count; i++) {
        log_info("Loading IP %s", ips->ips[i].ip);
        log_info("Port: %d", ips->ips[i].port);

        // Convert the IP to an integer
        struct in_addr addr;
        int ret = inet_pton(AF_INET, ips->ips[i].ip, &addr);
        if (ret != 1) {
            log_error("Failed to convert IP %s to integer", ips->ips[i].ip);
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        uint32_t port = ips->ips[i].port;

        ret = bpf_map_update_elem(port_map_fd, &addr.s_addr, &port, BPF_ANY);
        if (ret != 0) {
            log_error("Failed to update BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            goto cleanup_yaml;  
        }        
    }

cleanup_yaml:
    /* Free the data */
	cyaml_free(&config, &ips_schema, ips, 0);

    return ret;
}

int main(int argc, const char **argv) {
    return 0;
 struct l4_ *skel = NULL;
    int err;
    const char *config_file = NULL;

   

    if (config_file == NULL) {
        log_warn("Use default configuration file: %s", "config.yaml");
        config_file = "config.yaml";
    }

    /* Check if file exists */
    if (access(config_file, F_OK) == -1) {
        log_fatal("Configuration file %s does not exist", config_file);
        exit(1);
    }


    /* Open BPF application */
    skel = l4_lb_bpf__open();
    if (!skel) {
        log_fatal("Error while opening BPF skeleton");
        exit(1);
    }

    
    /* Set program type to XDP */
    bpf_program__set_type(skel->progs.xdp_hhdv1, BPF_PROG_TYPE_XDP);

    /* Load and verify BPF programs */
    if (l4_lb_bpf__load(skel)) {
        log_fatal("Error while loading BPF skeleton");
        exit(1);
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &sigint_handler;

    if (sigaction(SIGINT, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    if (sigaction(SIGTERM, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    /* Before attaching the program, we can load the map configuration */
    err = load_maps_config(config_file, skel);
    if (err) {
        log_fatal("Error while loading map configuration");
        goto cleanup;
    }

    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;

    err = attach_bpf_progs(xdp_flags, skel);
    if (err) {
        log_fatal("Error while attaching BPF programs");
        goto cleanup;
    }

    log_info("Successfully attached!");

    sleep(10000);

cleanup:
    cleanup_ifaces();
    l4_lb_bpf__destroy(skel);
    log_info("Program stopped correctly");
    return -err;
}