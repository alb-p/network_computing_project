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
    // __u64 load;
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
            log_info("Loaded backend IP %x", addr.s_addr);
            if (ret != 0) {
                log_error("Failed to update BPF map: %s", strerror(errno));
                ret = EXIT_FAILURE;
                goto cleanup_yaml;  
            }        

            struct load_s value = {
                .packets_rcvd = 0,
                .flows = 1,
            };

            ret = bpf_map_update_elem(load_map_fd, &addr.s_addr, &value, BPF_ANY);
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

        key = 2;
        struct in_addr addr_be;
        ret = inet_pton(AF_INET, root->backends[0].ip, &addr_be);
        if (ret != 1) {
            log_error("Failed to convert IP %s to integer", root->backends[0].ip);
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }
        ret = bpf_map_update_elem(utils_map_fd, &key, &addr_be, BPF_ANY);
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

    int update_min_load(struct l4_lb_bpf *skel, int num_be) {
        int err;
        int key = 2;
        __u32 min_be_ip;
        struct load_s curr_min_load;
        float min_load;

        int load_map_fd = bpf_map__fd(skel->maps.load);
        int backends_map_fd = bpf_map__fd(skel->maps.index_backend);
        int flow_backend_map_fd = bpf_map__fd(skel->maps.flow_backend);
        int utils_map_fd = bpf_map__fd(skel->maps.utils);

        if(load_map_fd < 0 || flow_backend_map_fd < 0 || utils_map_fd < 0 || backends_map_fd < 0){
            log_error("Failed to load BPF maps: %s", strerror(errno));
            return EXIT_FAILURE;
        }

        for (int i = 0; i<3; i++){
            __u32 res;
            bpf_map_lookup_elem(utils_map_fd, &i, &res);
            //debug previous line
            log_debug("Utils map: %x, i: %d", res, i);
        }

        //a for cicle to check if the backend are loaded correctly
        for (int i = 0; i < num_be; i++){
            __u32 res;
            bpf_map_lookup_elem(backends_map_fd, &i, &res);
            log_debug("Backend map: %x, i: %d", res, i);
            //check also the relative load
            struct load_s load;
            bpf_map_lookup_elem(load_map_fd, &res, &load);
            log_debug("Load map: %d, be_ip: %x", load.packets_rcvd, res);
        }

        key = 2;
        while(1){
            
            err = bpf_map_lookup_elem(utils_map_fd, &key, &min_be_ip);
            if(err < 0){
                log_error("Failed to lookup BPF map: %s", strerror(errno));
                return EXIT_FAILURE;
            }

            err = bpf_map_lookup_elem(load_map_fd, &min_be_ip, &curr_min_load);
            if(err < 0){
                log_error("Failed to update load BPF map:%x, %s",load_map_fd, strerror(errno));
                return EXIT_FAILURE;
            }

            min_load = (float) curr_min_load.packets_rcvd/curr_min_load.flows;
            log_debug("Min load: %f, backend_ip: %x", min_load, min_be_ip);
            for(int i = 0; i < num_be; i++){
                struct load_s load;
                //lookup for the backend ip in the backends map
                __u32 under_test_be_ip;
                err = bpf_map_lookup_elem(backends_map_fd, &i, &under_test_be_ip);
                err += bpf_map_lookup_elem(load_map_fd, &under_test_be_ip, &load);
                if(err < 0){
                    log_error("Failed to load BPF maps");
                    return EXIT_FAILURE;
                }
                float under_test_load = (float) load.packets_rcvd/load.flows;
                //log_debug 
                log_debug("Be_ip: %x, load: %f, #pkt: %d, #flows: %d", under_test_be_ip, under_test_load, load.packets_rcvd, load.flows);

                if((float) under_test_load < min_load){
                    min_load = under_test_load;
                    min_be_ip = i;
                    err = bpf_map_update_elem(utils_map_fd, &key, &under_test_be_ip, BPF_ANY);
                    if(err < 0){
                        log_error("Failed to update BPF map: %s", strerror(errno));
                        return EXIT_FAILURE;
                    }
                }

                //debug should wait some time before prints again all the info
                //usleep(100000);
            }  

            unsigned int mSeconds = 1000;
            usleep(mSeconds);
        }
        return EXIT_SUCCESS;

    }

    int main(int argc, const char **argv) {
        struct l4_lb_bpf *skel = NULL;
        cyaml_err_t err;
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
        const char *iface1 = "veth1";
        // sudo ip netns exec ns1 ./l4_lb
        int ifindex_iface1 = if_nametoindex(iface1);
        log_info("XDP program will be attached to %s interface (ifindex: %d)", iface1, ifindex_iface1);
        err = bpf_xdp_attach(ifindex_iface1, bpf_program__fd(skel->progs.l4_lb), xdp_flags, NULL);
        if (err) {
            log_fatal("Error while attaching 1st XDP program to the interface");
            goto cleanup;
        }

        log_info("Successfully attached!");
        update_min_load(skel, num_be);
        sleep(1000000);

    cleanup:
    bpf_xdp_detach(ifindex_iface1, xdp_flags, NULL);
        l4_lb_bpf__destroy(skel);
        log_info("Program stopped correctly");
        return -err;
    }