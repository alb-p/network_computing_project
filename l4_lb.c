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

    static int ifindex_iface1 = 0;

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

        /* Load the IPs in load map */
        for (int i = 0; i < root->backends_count; i++) {
            log_info("Loading IP %s", root->backends[i].ip);

            // Convert the IP to an integer
            struct in_addr addr;

            int ret = inet_pton(AF_INET, root->backends[i].ip, &addr);
            log_debug("COnverted IP %s to integer %d and saddr %d",root->backends[i].ip, addr, addr.s_addr );
            if (ret != 1) {
                log_error("Failed to convert IP %s to integer", root->backends[i].ip);
                ret = EXIT_FAILURE;
                goto cleanup_yaml;
            }

            // Now write the IP to the BPF map
            struct load_s value = {
                .flows = 1,
                .packets_rcvd = 0,
                .load = 1,
            };

            ret = bpf_map_update_elem(load_map_fd, &addr.s_addr, &value, BPF_ANY);
            if (ret != 0) {
                log_error("Failed to update BPF map: %s", strerror(errno));
                ret = EXIT_FAILURE;
                goto cleanup_yaml;  
            }        
        }



        // TODO: va mappata flow_backend? All'inizio è vuota :(
        /*
        int flow_backend_map_fd = bpf_map__fd(skel->maps.flow_backend);


        // Check if the file descriptor is valid
        if (flow_backend_map_fd < 0) {
            log_error("Failed to get file descriptor of flow_backend BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        Load the IPs in the BPF map 
        for (int i = 0; i < ; i++) {
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
        */
        

        int utils_map_fd = bpf_map__fd(skel->maps.utils);
        
        // Check if the file descriptor is valid
        if (utils_map_fd < 0) {
            log_error("Failed to get file descriptor of utils BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        __u8 key = 0;
        __u8 num_be = 0;

        //TODO controllare se vip va convertito in int
        struct in_addr addr;

        ret = inet_pton(AF_INET, root->vip, &addr);
        log_debug("Converted VIP %s to integer %d and saddr %d",root->vip, addr, addr.s_addr );
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

        for (int i = 0; i < root->backends_count; i++) {
            num_be += 1;
        }
        key = 1;
        ret = bpf_map_update_elem(utils_map_fd, &key, &num_be, BPF_ANY);
        if (ret != 0) {
            log_error("Failed to update BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            goto cleanup_yaml;  
        }
        
        key = 2;
        ret = bpf_map_update_elem(utils_map_fd, &key, root->backends[0].ip, BPF_ANY);
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

    int update_min_load(const char *config_file, struct l4_lb_bpf *skel, int num_be) {
        struct root *root;
        //int ret = EXIT_SUCCESS;
        int err;
        int key = 2;
        __u32 min_be_ip;
        struct load_s curr_min_load;
        float min_load;

        err = cyaml_load_file(config_file, &config, &root_schema, (void **) &root, NULL);
        if (err != CYAML_OK) {
            fprintf(stderr, "ERROR: %s\n", cyaml_strerror(err));
            return EXIT_FAILURE;
        }
        

        int load_map_fd = bpf_map__fd(skel->maps.load);
        int flow_backend_map_fd = bpf_map__fd(skel->maps.flow_backend);
        int utils_map_fd = bpf_map__fd(skel->maps.utils);

        if(load_map_fd < 0 || flow_backend_map_fd < 0 || utils_map_fd < 0){
            log_error("Failed to load BPF maps");
            return XDP_ABORTED;
        }

    

        while(1){
            err = bpf_map_lookup_elem(utils_map_fd, &key, &min_be_ip);
            if(err < 0){
                log_error("Failed to load BPF maps");
                return XDP_ABORTED;
            }
            err = bpf_map_lookup_elem(load_map_fd, &min_be_ip, &curr_min_load);
            if(err < 0){
                log_error("Failed to load BPF maps");
                return XDP_ABORTED;
            }

            min_load = curr_min_load.load;
            
            for(int i = 0; i < num_be; i++){
                struct load_s load;
                err = bpf_map_lookup_elem(load_map_fd, &root->backends[i].ip, &load);
                if(err < 0){
                    log_error("Failed to load BPF maps");
                    return XDP_ABORTED;
                }
                if(load.load <= min_load){
                    min_load = load.load;
                    // Convert the IP to an integer
                    struct in_addr addr;
                    int ret = inet_pton(AF_INET, root->backends[i].ip, &addr);
                    if (ret != 1) {
                        log_error("Failed to convert IP %s to integer", root->backends[i].ip);
                        ret = EXIT_FAILURE;
                        return XDP_ABORTED;
                    }
                    min_be_ip = addr.s_addr;
                }
            }  
        }
        return 0;

    }

    int main(int argc, const char **argv) {
        struct l4_lb_bpf *skel = NULL;
        int err;
        const char *config_file = NULL;
        int num_be;
        printf("starting .c");

    

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
        num_be = load_maps_config(config_file, skel);
        if (num_be < 0) {
            log_fatal("Error while loading map configuration");
            goto cleanup;
        }

        xdp_flags = 0;
        xdp_flags |= XDP_FLAGS_DRV_MODE;
        char* iface1 = "veth1";
        log_info("XDP program will be attached to %s interface", iface1);
        ifindex_iface1 = if_nametoindex(iface1);
        err = bpf_xdp_attach(ifindex_iface1, bpf_program__fd(skel->progs.l4_lb), xdp_flags, NULL);

        if (err) {
            log_fatal("Error while attaching 1st XDP program to the interface");
            goto cleanup;
        }

        log_info("Successfully attached!");
        update_min_load(config_file, skel, num_be);
        sleep(10000);

    cleanup:
        l4_lb_bpf__destroy(skel);
        log_info("Program stopped correctly");
        return -err;
    }