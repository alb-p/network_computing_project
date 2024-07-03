#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>
#include <stdint.h>

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



struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __type(key, __u32); //backendIndex
   __type(value, struct load_s);
   __uint(max_entries, 128);
} load SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_LRU_HASH);
   __type(key, struct flow_t);
   __type(value, __u32); //backendIndex
   __uint(max_entries, 65536);
} flow_backend SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __type(key, __u32); //backendIndex
   __type(value, __u32); //backend_ip
   __uint(max_entries, 4096);
} index_backend SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __type(key, __u32); //selector
   __type(value, __u32); //vip, # of BE
   __uint(max_entries, 128);
} utils SEC(".maps");

static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off, struct ethhdr **ethhdr) {
   struct ethhdr *eth = (struct ethhdr *)data;
   int hdr_size = sizeof(*eth);

   /* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
   if ((void *)eth + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *ethhdr = eth;

   return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr) {
   // ip header
   struct iphdr *ip = (struct iphdr *)(data + *nh_off);

   int hdr_size = sizeof(*ip);

   /* Byte-count bounds check; check if current pointer + size of header
    * is after data_end.
    */
   if ((void *)ip + hdr_size > data_end)
      return -1;

   hdr_size = ip->ihl * 4;
   if (hdr_size < sizeof(*ip))
      return -1;

   /* Variable-length IPv4 header, need to use byte-based arithmetic */
   if ((void *)ip + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *iphdr = ip;

   return ip->protocol;
}

static __always_inline int parse_udphdr(void *data, void *data_end, __u16 *nh_off, struct udphdr **udphdr) {
   struct udphdr *udp = data + *nh_off;
   int hdr_size = sizeof(*udp);

   if ((void *)udp + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *udphdr = udp;

   int len = bpf_ntohs(udp->len) - sizeof(struct udphdr);
   if (len < 0)
      return -1;

   return len;
}

__attribute__((__always_inline__)) static inline __u16 csum_fold_helper(
    __u64 csum)
{
  int i;
#pragma unroll
  for (i = 0; i < 4; i++)
  {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

__attribute__((__always_inline__)) static inline void ipv4_csum_inline(void *iph, __u64 *csum) {
  __u16 *next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
  for (int i = 0; i < sizeof(struct iphdr) >> 1; i++)
  {
    *csum += *next_iph_u16++;
  }
  *csum = csum_fold_helper(*csum);
}


static __always_inline int ipi_encap(struct xdp_md *ctx, __u32 dest_ip){
   void *data;
   void *data_end;
   struct iphdr *new_iph;
   struct iphdr *old_iph;
   struct ethhdr *new_eth;
   struct ethhdr old_eth;
   __u64 csum = -1;
   __u32 ip_len = 0;
   
   data = (void *)(long)ctx->data;
   data_end = (void *)(long)ctx->data_end;

   if ((void *)data + sizeof(struct ethhdr) > data_end)
      return -1;
   __builtin_memcpy(&old_eth, data, sizeof(struct ethhdr));

   old_iph = data + sizeof(struct ethhdr);
   if ((void *)data + sizeof(struct iphdr) > data_end)
      return -2;
   ip_len = old_iph->ihl * 4;

   
   if (bpf_xdp_adjust_head(ctx, 0 - ip_len)) {
      return -3;
   }
   data = (void *)(long)ctx->data;
   data_end = (void *)(long)ctx->data_end;

   new_eth = data;
   //copy old_eth in the new memory area
   if ((void *)new_eth + sizeof(struct ethhdr) > data_end)
      return -4;
   __builtin_memcpy(new_eth, &old_eth, sizeof(struct ethhdr));

   unsigned char temp_addr[ETH_ALEN];
   __builtin_memcpy(temp_addr, new_eth->h_dest, ETH_ALEN);
   __builtin_memcpy(new_eth->h_dest, new_eth->h_source, ETH_ALEN);
   __builtin_memcpy(new_eth->h_source, temp_addr, ETH_ALEN);


   //copy the old ip header in the new memory area
   new_iph = (void *)new_eth + sizeof(struct ethhdr);
   if ((void *)new_iph + sizeof(struct iphdr) > data_end)
      return -5;
   
   old_iph = data + sizeof(struct ethhdr) + ip_len;
   if((void *)old_iph + sizeof(struct iphdr) > data_end)
      return -6;

   new_iph->addrs = old_iph->addrs;
   new_iph->daddr = dest_ip;
   new_iph->frag_off = old_iph->frag_off;
   new_iph->id = old_iph->id;
   new_iph->ihl = old_iph->ihl;
   new_iph->protocol = IPPROTO_IPIP;
   new_iph->saddr = old_iph->saddr;
   new_iph->tos = old_iph->tos;
   new_iph->tot_len = bpf_htons(bpf_ntohs(old_iph->tot_len)+sizeof(struct iphdr));
   new_iph->ttl = old_iph->ttl;
   new_iph->version = old_iph->version;

   bpf_printk("DEST IP (after encapsulation): %x", dest_ip);

   ipv4_csum_inline(new_iph, &csum);
   new_iph->check = csum;

   return csum;
}



// Struct for callback context
struct callback_ctx {
    struct xdp_md *ctx;
    int min_index;
    unsigned long long min_ratio;
};

// Callback function to find the minimum packets_rcvd/flows ratio
static __u64 find_min_load(struct bpf_map *map, __u32 *key, struct load_s *value,
                            struct callback_ctx *data)
{
   //bpf_printk("Load backend %d, pkt:%d, flw:%llu", *key, value->packets_rcvd, value->flows);

   // Calculate the packets_rcvd/flows ratio multiplied by 100 for two decimal places
   unsigned long long ratio = 0;
   if (value->flows > 0) {
       ratio = (value->packets_rcvd * 100) / value->flows;
   }

   __u32 *dest_ip = bpf_map_lookup_elem(&index_backend, key);
   if(dest_ip){
      //bpf_printk("Destination backend: %x", *dest_ip);
   } else {
      bpf_printk("It was not possible to lookup for the backend IP");
      return XDP_ABORTED;
   }
   // Print ratio
   //bpf_printk("Ratio: %llu", ratio);
   //bpf_printk("Data_min_ratio: %llu", data->min_ratio);
   if(data->min_index == -1){
      bpf_printk("|--------------------------------------------------|");
      bpf_printk("|Id--------Pkt-------flw-------rat-------destIp----|");
      data->min_ratio = ratio;
      data->min_index = *key;
   }else{
      // Check if this ratio is smaller than the current minimum
      if (ratio <= data->min_ratio) {
         data->min_ratio = ratio;
         data->min_index = *key;  // Save the key (index) of the minimum element
      }
   }
   bpf_printk("|%-10d%-10d%-10d%-10llu%-10x|", *key, value->packets_rcvd, value->flows, ratio, *dest_ip);
   return 0;  // Always return 0 to continue iteration
}

static __always_inline __u32 find_min_load_be_index(struct xdp_md *ctx){
   //bpf_printk("Finding the min load backend");
   __u32 key = 2;
   int res = -1;

   __u32 *local_min_load = bpf_map_lookup_elem(&utils, &key);
      if (!local_min_load){
         bpf_printk("It was not possible to lookup for the local min load");
         return XDP_ABORTED;
      } else {
         bpf_printk("Local_min_load %d", *local_min_load);
      }

   struct callback_ctx data = {
        .min_index = -1,
        .min_ratio = 1000000,
   };
   bpf_for_each_map_elem(&load, find_min_load, &data, 0);

   bpf_printk("|--------------------------------------------------|");
   //bpf_printk("Data dopo each_map: %llu, min_index %d", data.min_ratio, data.min_index);

   return data.min_index;
   
}

SEC("xdp")
int l4_lb(struct xdp_md *ctx) {
   void *data_end = (void *)(long)ctx->data_end;
   void *data = (void *)(long)ctx->data;
   int eth_type, ip_type;
   struct flow_t flow;
   __u16 nf_off = 0;
   struct ethhdr *eth;
   struct udphdr *udp;
   int action = XDP_PASS;
   bpf_printk("Packet received");


   eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);
   
   if (eth_type != bpf_htons(ETH_P_IP)) {
      bpf_printk("Packet is not an IPv4 packet");
      return XDP_DROP;
   }
   bpf_printk("Packet is a valid IPv4 packet");


   // Handle IPv4 and parse UDP headers
   struct iphdr *ip;
   ip_type = parse_iphdr(data, data_end, &nf_off, &ip);

   if (ip_type == IPPROTO_UDP) {
      bpf_printk("Packet is UDP");
      if (parse_udphdr(data, data_end, &nf_off, &udp) < 0) {
         goto drop;
      }
   } else {
      bpf_printk("Packet is not UDP");
      goto drop;
   }

   int key = 0;
   __u32 *vip = bpf_map_lookup_elem(&utils, &key);
   if(vip){
      //bpf_printk("VIP: %x", *vip);
   } else {
      bpf_printk("It was not possible to lookup for the VIP");
      return XDP_ABORTED;
   }

   bpf_printk("VIP: %x", *vip);
   bpf_printk("Destination IP: %x", ip->daddr);
  
   if(ip->daddr != *vip){
      bpf_printk("Packet is not for the VIP");

      goto drop;
   }

   /* create a 5-tuple of the just arrived connection, it will be the key to search for the flow in the map */
   flow.IPsrc = ip->saddr;
   flow.IPdst = ip->daddr;
   flow.srcPort = udp->source;
   flow.dstPort = udp->dest;
   flow.protocol = ip_type;

   bpf_printk("Flows info: IPsrc:%x,IPdst:%x, srcPort:%u,dstPort:%u, proto:%d", flow.IPsrc,flow.IPdst, flow.srcPort, flow.dstPort, flow.protocol);

   //eventually existing flow's structure
   struct flow_t *existing_flow;
   //backend ip to which the flow will be direct 
   __u32 *be_index;
   //selected backend's load info structure
   struct load_s *load_be;
   int res = -1;

   /* lookup on the map to see if the flow is already assigned to a backend and in that case it returns it */
   be_index = bpf_map_lookup_elem(&flow_backend, &flow);
   
   
   if(be_index != NULL){
      //flow is already existing, take the load info
      bpf_printk("Flow existing: %x", *be_index);
      load_be = bpf_map_lookup_elem(&load, be_index);
      if (!load_be){
         bpf_printk("Flow existing. It was not possible to lookup for the load");
         return XDP_ABORTED;
      }

      //bpf_printk("Load of the selected backend(%x): %d", *be_index, load_be->packets_rcvd);

      __sync_fetch_and_add(&load_be->packets_rcvd, 1);

   } else { //create a new bond between the flow and the backend with minimum load
      // retrieve the load min backend
      bpf_printk("Flow not found");
      __u32 be_min_index = -1;
      be_min_index = find_min_load_be_index(ctx);
      //be_min_index = find_for_min_load_be_index(ctx);

      if (be_min_index >= 0) {
         bpf_printk("Selected backend by find_: %x", be_min_index);
         res = bpf_map_update_elem(&flow_backend, &flow, &be_min_index, BPF_ANY);
         if (res < 0) {
            bpf_printk("An error occurred during the association of a new flow");
            return XDP_ABORTED;
         }

         __u32 *be_flow= bpf_map_lookup_elem(&flow_backend, &flow);
         if(be_flow){
            //bpf_printk("Flow associated to backend: %x", *be_flow);
         } else {
            bpf_printk("It was not possible to lookup for the backend IP");
            return XDP_ABORTED;
         }

         
         // update the laod (pkt and flow)
         load_be = bpf_map_lookup_elem(&load, &be_min_index);
         if (!load_be){
            bpf_printk("It was not possible to lookup for the load");
            return XDP_ABORTED;
         } else {
            //bpf_printk("Load of the selected backend(%x): %llu",be_min_index, load_be->packets_rcvd/load_be->flows);
         }
         __sync_fetch_and_add(&load_be->packets_rcvd, 1);
         __sync_fetch_and_add(&load_be->flows, 1);

        
      } else {
         bpf_printk("Failed to find the min load backend IP");
         return XDP_ABORTED;
      }
      
      

   }
   __u32 *be_flow;
   be_flow = bpf_map_lookup_elem(&flow_backend, &flow);
   if(be_flow){
         bpf_printk("Backend associated to flow: %x", *be_flow);
      } else {
         bpf_printk("__It was not possible to lookup for the backend IP");
         return XDP_ABORTED;
      }

   __u32 *dest_ip = bpf_map_lookup_elem(&index_backend, be_flow);
      if(dest_ip){
         //bpf_printk("Destination backend: %x", *dest_ip);
      } else {
         //bpf_printk("It was not possible to lookup for the backend IP__");
         return XDP_ABORTED;
      }
   find_min_load_be_index(ctx);

   //IP-to-IP encapsulation   
   res = ipi_encap(ctx, *dest_ip);
   if(res < 0){
      bpf_printk("It was not possible to encapsulate the packet, res: %d\n", res);
      return XDP_ABORTED;
   }

   
   bpf_printk("sending back\n");
   return XDP_TX;

   


drop:
return XDP_DROP;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";