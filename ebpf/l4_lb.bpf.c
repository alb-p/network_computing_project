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
   __u64 load;
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
   __uint(max_entries, 1024);
} load SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_HASH);;
   __type(key, struct flow_t);
   __type(value, __u32); //backendIP
   __uint(max_entries, 65536);
} flow_backend SEC(".maps");

struct {
   __uint(type, BPF_MAP_TYPE_ARRAY);
   __type(key, int); //selettore
   __type(value, __u32); //vip, numero be, beIP_min_load
   __uint(max_entries, 1024);
} utils SEC(".maps");


// TODO: arp?

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
         action = XDP_ABORTED;
         goto drop;
      }
   } else if (ip_type == IPPROTO_TCP) {
      bpf_printk("Packet is TCP");
      action = XDP_ABORTED;
   } else {
      bpf_printk("Packet is not TCP or UDP");
      action = XDP_ABORTED;
      goto drop;
   }

   //crea 5-tupla della connessione appena arrivata, sarà chiave per cercare il flow nella map
   __u16 port = bpf_htons(bpf_ntohs(udp->dest) - 1);
      if (port > 0)
         udp->dest = port;
   
   flow.IPsrc = ip->addrs.saddr;
   flow.IPdst = ip->addrs.daddr;
   flow.srcPort = udp->source;
   flow.dstPort = udp->dest;
   flow.protocol = ip_type;

   bpf_printk("Flows info: IPsrc:%u,IPdst:%u, srcPort:%u,dstPort:%u, proto:%d", flow.IPsrc,flow.IPdst, flow.srcPort, flow.dstPort, flow.protocol);

   struct flow_t *existing_flow;
   __u32 *be_ip;
   struct load_s *load_be;
   int res = -1;

   //lookup sulla mappa per vedere se il flow esiste già. nel caso ritorna un flow
   be_ip = bpf_map_lookup_elem(&flow_backend, &flow.dstPort);
   if(be_ip != NULL){
      // esiste già il flow, prendo il LOAD
      
      load_be = bpf_map_lookup_elem(&load, &be_ip);
      load_be->packets_rcvd +=1;
      load_be->load = load_be->packets_rcvd/load_be->flows;
      // __sync_fetch_and_add(&load_be->packets_rcvd, 1);

      res = bpf_map_update_elem(&load, &be_ip, load_be, BPF_EXIST);
      if(res < 0){
         bpf_printk("It was not possible to update the load");
         return XDP_ABORTED;
      }

   } else {
      // creo il nuovo flow, su backend con LOAD min

      // retrieve the load min backend
      
      int key = 2; 
      __u32 *be_ip_ptr = bpf_map_lookup_elem(&utils, &key);

      if (be_ip_ptr) {
         __u32 be_ip = *be_ip_ptr;
         // Now you can use be_ip as a __u32
      } else {
         // Handle the case where the lookup failed
      }

      // add the connection bw new flow and backend
      res = bpf_map_update_elem(&flow_backend, &flow ,be_ip, BPF_NOEXIST);
      if(res < 0){
         bpf_printk("An error occured during the association of a new flow");
         return XDP_ABORTED;
      }

      // update the laod (pkt and flow)
      load_be = bpf_map_lookup_elem(&load, &be_ip);
      load_be->packets_rcvd +=1;
      load_be->flows +=1;
      load_be->load = load_be->packets_rcvd/load_be->flows;
      // __sync_fetch_and_add(&load_be->packets_rcvd, 1);

      int res = bpf_map_update_elem(&load, &be_ip, load_be, BPF_EXIST);
      if(res < 0){
         bpf_printk("It was not possible to update the load");
         return XDP_ABORTED;
      }

   }


   //encapsulation
   //ip_in_ip_encapsulation(be_ip, )





   return XDP_DROP;
drop:
return XDP_DROP;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";