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

    static const char *const usages[] = {
    "l4_lb [options] [[--] args]",
    "l4_lb [options]",
    NULL,
    };

    struct load_s {
    __u64 packets_rcvd;
    __u64 flows;
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

        log_info("Loaded %d backends", root->backends_count);

        // Get file descriptor of the map
        int load_map_fd = bpf_map__fd(skel->maps.load);
        
        // Check if the file descriptor is valid
        if (load_map_fd < 0) {
            log_error("Failed to get file descriptor of BPF map load: %s", strerror(errno));
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        // File descriptor of index_backend map
        int backends_map_fd = bpf_map__fd(skel->maps.index_backend);
        if (backends_map_fd < 0) {
            log_error("Failed to get file descriptor of BPF map backends: %s", strerror(errno));
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        /* Load the backends IPs in backends map and loads in laod map */
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

            ret = bpf_map_update_elem(backends_map_fd, &i, &addr.s_addr, BPF_ANY);
            log_info("Loaded backend IP %x, index %d", addr.s_addr, i);
            if (ret != 0) {
                log_error("Failed to update BPF map: %s", strerror(errno));
                ret = EXIT_FAILURE;
                goto cleanup_yaml;  
            }        

            struct load_s value = {
                .packets_rcvd = 0,
                .flows = 1,
            };
            ret = bpf_map_update_elem(load_map_fd, &i, &value, BPF_ANY);
            if (ret != 0) {
                log_error("Failed to update BPF map: %s", strerror(errno));
                ret = EXIT_FAILURE;
                goto cleanup_yaml;  
            }  
        }

        int utils_map_fd = bpf_map__fd(skel->maps.utils);
        
        // Check if the file descriptor is valid
        if (utils_map_fd < 0) {
            log_error("Failed to get file descriptor of utils BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        __u32 key = 0;
        struct in_addr addr;

        ret = inet_pton(AF_INET, root->vip, &addr);
        log_debug("Converted VIP %s to integer %d and saddr %x",root->vip, addr, addr.s_addr );
        if (ret != 1) {
            log_error("Failed to convert IP %s to integer", root->vip);
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }    

        if (bpf_map_update_elem(utils_map_fd, &key, &addr.s_addr, BPF_ANY)) {
                log_error("Failed to update BPF map: %s", strerror(errno));
                ret = EXIT_FAILURE;
                goto cleanup_yaml;  
        }  

        key = 1;
        __u32 num_be = 0;
        for (int i = 0; i < root->backends_count; i++) {
            num_be += 1;
        }
        ret = bpf_map_update_elem(utils_map_fd, &key, &num_be, BPF_ANY);
        if (ret != 0) {
            log_error("Failed to update BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            goto cleanup_yaml;  
        }

        return num_be;

    cleanup_yaml:
        /* Free the data */
        cyaml_free(&config, &root_schema, root, 0);
        return ret;
    }

    int start_info_print(struct l4_lb_bpf *skel, int num_be){
        
        int load_map_fd = bpf_map__fd(skel->maps.load);
        int backends_map_fd = bpf_map__fd(skel->maps.index_backend);
        int flow_backend_map_fd = bpf_map__fd(skel->maps.flow_backend);
        int utils_map_fd = bpf_map__fd(skel->maps.utils);

        if(load_map_fd < 0 || flow_backend_map_fd < 0 || utils_map_fd < 0 || backends_map_fd < 0){
            log_error("Failed to load BPF maps: %s", strerror(errno));
            return EXIT_FAILURE;
        }

        //debug utils map
        for (int i = 0; i<2; i++){
            __u32 res;
            bpf_map_lookup_elem(utils_map_fd, &i, &res);
            log_debug("Utils map: %x, i: %d", res, i);
        }

        //a for cicle to check if the backend are loaded correctly
        for (int i = 0; i < num_be; i++){
            __u32 res;
            bpf_map_lookup_elem(backends_map_fd, &i, &res);
            log_debug("Backend map: %x, i: %d", res, i);
            //check also the relative load
            struct load_s load;
            bpf_map_lookup_elem(load_map_fd, &i, &load);
            log_debug("Load map: %d, be_ip: %x", load.packets_rcvd, res);
        }

        for (int i = 0; i < num_be; i++){
            __u32 res;
            bpf_map_lookup_elem(flow_backend_map_fd, &i, &res);
            log_debug("Flow-Backend map: %x, i: %d", res, i);
        }
        return 0;

    }


    int main(int argc, const char **argv) {
        struct l4_lb_bpf *skel = NULL;
        cyaml_err_t err;
        const char *config_file = NULL;
        const char *iface = NULL;

        struct argparse_option options[] = {
            OPT_HELP(),
            OPT_GROUP("Basic options"),
            OPT_STRING('c', "config", &config_file, "Path to the YAML configuration file", NULL, 0, 0),
            OPT_STRING('i', "iface", &iface, "Interface where to attach the BPF program", NULL, 0, 0),
            OPT_END(),
        };   
        struct argparse argparse;
        argparse_init(&argparse, options, usages, 0);
        argparse_describe(&argparse,
                        "\nA Layer 4 load balancer operates at the transport layer of the OSI model,"
                        "\ndirecting client requests based on data from network and transport "
                        "\nlayer protocols, such as IP addresses and TCP/UDP ports.",
                        "\nThe '-i' argument is used to specify the "
                        "interface where to attach the program");
        argc = argparse_parse(&argparse, argc, argv);


        if (iface == NULL) {
            log_warn("Use default interface: %s", "veth1");
            iface = "veth1";
        }   

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
        bpf_program__set_type(skel->progs.l4_lb, BPF_PROG_TYPE_XDP);

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
        int num_be = 0;
        num_be = load_maps_config(config_file, skel);

        if (num_be < 0) {
            log_fatal("Error while loading map configuration");
            goto cleanup;
        }

        xdp_flags = 0;
        xdp_flags |= XDP_FLAGS_DRV_MODE;
        //const char *iface1 = "veth1";
        // sudo ip netns exec ns1 ./l4_lb
        int ifindex_iface1 = if_nametoindex(iface);
        log_info("XDP program will be attached to %s interface (ifindex: %d)", iface, ifindex_iface1);
        err = bpf_xdp_attach(ifindex_iface1, bpf_program__fd(skel->progs.l4_lb), xdp_flags, NULL);
        if (err) {
            log_fatal("Error while attaching 1st XDP program to the interface");
            goto cleanup;
        }
        

        log_info("Successfully attached!");
        //start_info_print(skel, num_be);
        sleep(10000);

    cleanup:
    bpf_xdp_detach(ifindex_iface1, xdp_flags, NULL);
        l4_lb_bpf__destroy(skel);
        log_info("Program stopped correctly");
        return -err;
    }