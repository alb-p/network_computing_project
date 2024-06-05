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

#define BE_MIN_LOAD 2


// bpf_l3_csum_replace

struct load_s {
   __u64 packets_rcvd;
   __u64 flows;
   //computed
   __u64 c_load;
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
    __type(key, __u32); //backendIP
   __type(value, struct load_s);
   __uint(max_entries, 65536);
} load SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __type(key, struct flow_t);
   __type(value, __u32); //backendIP
   __uint(max_entries, 65536);
} flow_backend SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __type(key, __u32); //selettore
   __type(value, __u32); //vip, numero be, beIP_min_load
   __uint(max_entries, 65536);
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

static __always_inline int ipi_encap(struct xdp_md *ctx, __u32 be_ip){
   void *data;
   void *data_end;
   struct iphdr *new_iph;
   struct iphdr *old_iph;
   struct ethhdr *new_eth;
   struct ethhdr *old_eth;
   __u64 csum = 0;

   if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct iphdr)))
   {
      return -1;
   }
   
   data = (void *)(long)ctx->data;
   data_end = (void *)(long)ctx->data_end;
   old_eth = data;
   old_iph = data + sizeof(struct ethhdr);

   
   data = (void *)(long)ctx->data;
   data_end = (void *)(long)ctx->data_end;

   new_eth = data;
   new_iph = data + sizeof(struct ethhdr);
   
   if ((void *)new_eth + 1 > data_end || (void *)old_eth + 1 > data_end || (void *)new_iph + (sizeof(struct iphdr)) > data_end){
         return -1;
   }
   
   //copy all the field of old_eth to new_eth
   __builtin_memcpy(new_eth->h_dest, old_eth->h_dest, 6);
   __builtin_memcpy(new_eth->h_source, old_eth->h_source, 6);
   new_eth->h_proto = bpf_htons(ETH_P_IP);

   new_iph->addrs = old_iph->addrs;
   new_iph->daddr = be_ip;
   new_iph->frag_off = old_iph->frag_off;
   new_iph->id = old_iph->id;
   new_iph->ihl = old_iph->ihl;
   new_iph->protocol = IPPROTO_IPIP;
   new_iph->saddr = old_iph->saddr;
   new_iph->tos = old_iph->tos;
   new_iph->tot_len = bpf_htons(bpf_ntohs(old_iph->tot_len)+bpf_htons(sizeof(struct iphdr)));
   new_iph->ttl = old_iph->ttl;
   new_iph->version = old_iph->version;

   ipv4_csum_inline(new_iph, &csum);
   new_iph->check = csum;

   return 1;
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

   //crea 5-tupla della connessione appena arrivata, sarà chiave per cercare il flow nella map


   flow.IPsrc = ip->saddr;
   flow.IPdst = ip->daddr;
   flow.srcPort = udp->source;
   flow.dstPort = udp->dest;
   flow.protocol = ip_type;

   bpf_printk("Flows info: IPsrc:%u,IPdst:%u, srcPort:%u,dstPort:%u, proto:%d", flow.IPsrc,flow.IPdst, flow.srcPort, flow.dstPort, flow.protocol);

   //eventually existing flow's structure
   struct flow_t *existing_flow;
   //backend ip to which the flow will be direct 
   __u32 *be_ip;
   //selected backend's load info structure
   struct load_s *load_be;
   int res = -1;

   //lookup sulla mappa per vedere se il flow esiste già. nel caso ritorna un flow
   be_ip = bpf_map_lookup_elem(&flow_backend, &flow);
   if(be_ip != NULL){
      //flow is already existing, take the load info
      load_be = bpf_map_lookup_elem(&load, &be_ip);
      if (!load_be){
         bpf_printk("It was not possible to lookup for the load");
         return XDP_ABORTED;
      }
      bpf_printk("Load of the selected backend: %d", load_be->c_load);
      load_be->packets_rcvd = load_be->packets_rcvd +1;
      if (load_be->flows > 0) {
         load_be->c_load = load_be->packets_rcvd / load_be->flows;
      } else {
         load_be->c_load = load_be->packets_rcvd;
      }

      

      res = bpf_map_update_elem(&load, &be_ip, load_be, BPF_EXIST);
      if(res < 0){
         bpf_printk("It was not possible to update the load");
         return XDP_ABORTED;
      }

   } else { //devo creare il nuovo legame tra flow e il backend con min load
      // retrieve the load min backend
      int key = 2; 
      __u32 *be_ip_ptr = bpf_map_lookup_elem(&utils, &key);
      be_ip = be_ip_ptr;
      if (be_ip_ptr) {
         __u32 be_ip_val = *be_ip_ptr;
         res = bpf_map_update_elem(&flow_backend, &flow, &be_ip_val, BPF_NOEXIST);
         if (res < 0) {
            bpf_printk("An error occurred during the association of a new flow");
            return XDP_ABORTED;
         }
         // update the laod (pkt and flow)
         load_be = bpf_map_lookup_elem(&load, &be_ip_val);
         if (!load_be){
            bpf_printk("It was not possible to lookup for the load");
            return XDP_ABORTED;
         }
         load_be->packets_rcvd +=1;
         load_be->flows +=1;
         load_be->c_load = load_be->packets_rcvd/load_be->flows;

         res = bpf_map_update_elem(&load, &be_ip_val, load_be, BPF_EXIST);
         if(res < 0){
            bpf_printk("It was not possible to update the load");
            return XDP_ABORTED;
         } else {
         bpf_printk("Could not find backend with minimum load");
         return XDP_ABORTED;
         }
      }

   }

   //IP-to-IP encapsulation   
   //res = ipi_encap(ctx, *be_ip);
   //args->dst_mac, bpf_htonl(args->saddr), bpf_htonl(args->daddr), payload_len);
   if(res < 0){
            bpf_printk("It was not possible to encapsulate the packet");
            return XDP_ABORTED;
         }
   bpf_printk("sending back %d", res);
   return XDP_TX;

   


drop:
return XDP_DROP;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";