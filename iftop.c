/*
 * iftop.c:
 *
 */

#include "integers.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
/* include <net/bpf.h> -- this was added by the PFLOG patch but seems
 * superfluous and breaks on Slackware */
#if defined(HAVE_PCAP_H)
#   include <pcap.h>
#elif defined(HAVE_PCAP_PCAP_H)
#   include <pcap/pcap.h>
#else
#   error No pcap.h
#endif

#include <pthread.h>
#include <curses.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>

#include "iftop.h"
#include "addr_hash.h"
#include "resolver.h"
#include "ui.h"
#include "options.h"
#ifdef DLT_LINUX_SLL
#include "sll.h"
#endif /* DLT_LINUX_SLL */
#include "threadprof.h"
#include "ether.h"
#include "ip.h"
#include "tcp.h"
#include "token.h"
#include "llc.h"
#include "extract.h"
#include "ethertype.h"
#include "cfgfile.h"
#include "ppp.h"

#include <netinet/ip6.h>

/* ethernet address of interface. */
int have_hw_addr = 0;
unsigned char if_hw_addr[6];    

/* IP address of interface */
int have_ip_addr = 0;
int have_ip6_addr = 0;
struct in_addr if_ip_addr;
struct in6_addr if_ip6_addr;

extern options_t options;

hash_type* history;
history_type history_totals;
time_t last_timestamp;
int history_pos = 0;
int history_len = 1;
pthread_mutex_t tick_mutex;

pcap_t* pd; /* pcap descriptor */
struct bpf_program pcap_filter;
pcap_handler packet_handler;

sig_atomic_t foad;

static void finish(int sig) {
    foad = sig;
}




/* Only need ethernet (plus optional 4 byte VLAN) and IP headers (48) + first 2
 * bytes of tcp/udp header */
/* Increase with a further 20 to account for IPv6 header length.  */
/* IEEE 802.11 radiotap throws in a variable length header plus 8 (radiotap
 * header header) plus 34 (802.11 MAC) plus 40 (IPv6) = 78, plus whatever's in
 * the radiotap payload */
/*#define CAPTURE_LENGTH 92 */
#define CAPTURE_LENGTH 256

void init_history() {
    history = addr_hash_create();
    last_timestamp = time(NULL);
    memset(&history_totals, 0, sizeof history_totals);
}

history_type* history_create() {
    history_type* h;
    h = xcalloc(1, sizeof *h);
    return h;
}

void history_rotate() {
    hash_node_type* n = NULL;
    history_pos = (history_pos + 1) % HISTORY_LENGTH;
    hash_next_item(history, &n);
    while(n != NULL) {
        hash_node_type* next = n;
        history_type* d = (history_type*)n->rec;
        hash_next_item(history, &next);

        if(d->last_write == history_pos) {
            addr_pair key = *(addr_pair*)(n->key);
            hash_delete(history, &key);
            free(d);
        }
        else {
            d->recv[history_pos] = 0;
            d->sent[history_pos] = 0;
        }
        n = next; 
    }

    history_totals.sent[history_pos] = 0;
    history_totals.recv[history_pos] = 0;

    if(history_len < HISTORY_LENGTH) {
        history_len++;
    }
}


void tick(int print) {
    time_t t;

    pthread_mutex_lock(&tick_mutex);
   
    t = time(NULL);
    if(t - last_timestamp >= RESOLUTION) {
        //printf("TICKING\n");
        analyse_data();
        ui_print();
        history_rotate();
        last_timestamp = t;
    }
    else {
      ui_tick(print);
    }

    pthread_mutex_unlock(&tick_mutex);
}

int in_filter_net(struct in_addr addr) {
    int ret;
    ret = ((addr.s_addr & options.netfiltermask.s_addr) == options.netfilternet.s_addr);
    return ret;
}

int __inline__ ip_addr_match(struct in_addr addr) {
    return addr.s_addr == if_ip_addr.s_addr;
}

int __inline__ ip6_addr_match(struct in6_addr *addr) {
    return IN6_ARE_ADDR_EQUAL(addr, &if_ip6_addr);
}

/**
 * Creates an addr_pair from an ip (and tcp/udp) header, swapping src and dst
 * if required
 */
void assign_addr_pair(addr_pair* ap, struct ip* iptr, int flip) {
  unsigned short int src_port = 0;
  unsigned short int dst_port = 0;

  /* Arrange for predictable values. */
  memset(ap, '\0', sizeof(*ap));

  if(IP_V(iptr) == 4) {
    ap->af = AF_INET;
  /* Does this protocol use ports? */
  if(iptr->ip_p == IPPROTO_TCP || iptr->ip_p == IPPROTO_UDP) {
    /* We take a slight liberty here by treating UDP the same as TCP */

    /* Find the TCP/UDP header */
    struct tcphdr* thdr = ((void*)iptr) + IP_HL(iptr) * 4;
    src_port = ntohs(thdr->th_sport);
    dst_port = ntohs(thdr->th_dport);
  }

  if(flip == 0) {
    ap->src = iptr->ip_src;
    ap->src_port = src_port;
    ap->dst = iptr->ip_dst;
    ap->dst_port = dst_port;
  }
  else {
    ap->src = iptr->ip_dst;
    ap->src_port = dst_port;
    ap->dst = iptr->ip_src;
    ap->dst_port = src_port;
  }
  } /* IPv4 */
  else if (IP_V(iptr) == 6) {
    /* IPv6 packet seen. */
    struct ip6_hdr *ip6tr = (struct ip6_hdr *) iptr;

    ap->af = AF_INET6;

    if( (ip6tr->ip6_nxt == IPPROTO_TCP) || (ip6tr->ip6_nxt == IPPROTO_UDP) ) {
      struct tcphdr *thdr = ((void *) ip6tr) + 40;

      src_port = ntohs(thdr->th_sport);
      dst_port = ntohs(thdr->th_dport);
    }

    if(flip == 0) {
      memcpy(&ap->src6, &ip6tr->ip6_src, sizeof(ap->src6));
      ap->src_port = src_port;
      memcpy(&ap->dst6, &ip6tr->ip6_dst, sizeof(ap->dst6));
      ap->dst_port = dst_port;
    }
    else {
      memcpy(&ap->src6, &ip6tr->ip6_dst, sizeof(ap->src6));
      ap->src_port = dst_port;
      memcpy(&ap->dst6, &ip6tr->ip6_src, sizeof(ap->dst6));
      ap->dst_port = src_port;
    }
  }
}

static void handle_ip_packet(struct ip* iptr, int hw_dir)
{
    int direction = 0; /* incoming */
    history_type* ht;
    union {
      history_type **ht_pp;
      void **void_pp;
    } u_ht = { &ht };
    addr_pair ap;
    unsigned int len = 0;
    struct in6_addr scribdst;   /* Scratch pad. */
    struct in6_addr scribsrc;   /* Scratch pad. */
    /* Reinterpret packet type. */
    struct ip6_hdr* ip6tr = (struct ip6_hdr *) iptr;

    memset(&ap, '\0', sizeof(ap));

    if( (IP_V(iptr) ==4 && options.netfilter == 0)
            || (IP_V(iptr) == 6 && options.netfilter6 == 0) ) { 
        /*
         * Net filter is off, so assign direction based on MAC address
         */
        if(hw_dir == 1) {
            /* Packet leaving this interface. */
            assign_addr_pair(&ap, iptr, 0);
            direction = 1;
        }
        else if(hw_dir == 0) {
            /* Packet incoming */
            assign_addr_pair(&ap, iptr, 1);
            direction = 0;
        }
        /* Packet direction is not given away by h/ware layer.  Try IP
         * layer
         */
        else if((IP_V(iptr) == 4) && have_ip_addr && ip_addr_match(iptr->ip_src)) {
            /* outgoing */
            assign_addr_pair(&ap, iptr, 0);
            direction = 1;
        }
        else if((IP_V(iptr) == 4) && have_ip_addr && ip_addr_match(iptr->ip_dst)) {
            /* incoming */
            assign_addr_pair(&ap, iptr, 1);
            direction = 0;
        }
        else if((IP_V(iptr) == 6) && have_ip6_addr && ip6_addr_match(&ip6tr->ip6_src)) {
            /* outgoing */
            assign_addr_pair(&ap, iptr, 0);
            direction = 1;
        }
        else if((IP_V(iptr) == 6) && have_ip6_addr && ip6_addr_match(&ip6tr->ip6_dst)) {
            /* incoming */
            assign_addr_pair(&ap, iptr, 1);
            direction = 0;
        }
        /*
         * Cannot determine direction from hardware or IP levels.  Therefore 
         * assume that it was a packet between two other machines, assign
         * source and dest arbitrarily (by numerical value) and account as 
         * incoming.
         */
	else if (options.promiscuous_but_choosy) {
	    return;		/* junk it */
	}
        else if((IP_V(iptr) == 4) && (iptr->ip_src.s_addr < iptr->ip_dst.s_addr)) {
            assign_addr_pair(&ap, iptr, 1);
            direction = 0;
        }
        else if(IP_V(iptr) == 4) {
            assign_addr_pair(&ap, iptr, 0);
            direction = 0;
        }
        /* Drop other uncertain packages. */
    }

    if(IP_V(iptr) == 4 && options.netfilter != 0) {
        /* 
         * Net filter on, assign direction according to netmask 
         */ 
        if(in_filter_net(iptr->ip_src) && !in_filter_net(iptr->ip_dst)) {
            /* out of network */
            assign_addr_pair(&ap, iptr, 0);
            direction = 1;
        }
        else if(in_filter_net(iptr->ip_dst) && !in_filter_net(iptr->ip_src)) {
            /* into network */
            assign_addr_pair(&ap, iptr, 1);
            direction = 0;
        }
        else {
            /* drop packet */
            return ;
        }
    }

    if(IP_V(iptr) == 6 && options.netfilter6 != 0) {
        /*
         * Net filter IPv6 active.
         */
        int j;
        //else if((IP_V(iptr) == 6) && have_ip6_addr && ip6_addr_match(&ip6tr->ip6_dst)) {
        /* First reduce the participating addresses using the netfilter prefix.
         * We need scratch pads to do this.
         */
        for (j=0; j < 16; ++j) {
            scribdst.s6_addr[j] = ip6tr->ip6_dst.s6_addr[j]
                                        & options.netfilter6mask.s6_addr[j];
            scribsrc.s6_addr[j] = ip6tr->ip6_src.s6_addr[j]
                                        & options.netfilter6mask.s6_addr[j];
        }

        /* Now look for any hits. */
        //if(in_filter_net(iptr->ip_src) && !in_filter_net(iptr->ip_dst)) {
        if (IN6_ARE_ADDR_EQUAL(&scribsrc, &options.netfilter6net)
                && ! IN6_ARE_ADDR_EQUAL(&scribdst, &options.netfilter6net)) {
            /* out of network */
            assign_addr_pair(&ap, iptr, 0);
            direction = 1;
        }
        //else if(in_filter_net(iptr->ip_dst) && !in_filter_net(iptr->ip_src)) {
        else if (! IN6_ARE_ADDR_EQUAL(&scribsrc, &options.netfilter6net)
                    && IN6_ARE_ADDR_EQUAL(&scribdst, &options.netfilter6net)) {
            /* into network */
            assign_addr_pair(&ap, iptr, 1);
            direction = 0;
        }
        else {
            /* drop packet */
            return ;
        }
    }

#if 1
    /* Test if link-local IPv6 packets should be dropped. */
    if( IP_V(iptr) == 6 && !options.link_local
            && (IN6_IS_ADDR_LINKLOCAL(&ip6tr->ip6_dst)
                || IN6_IS_ADDR_LINKLOCAL(&ip6tr->ip6_src)) )
        return;
#endif

    /* Do address resolving. */
    switch (IP_V(iptr)) {
      case 4:
          ap.protocol = iptr->ip_p;
          /* Add the addresses to be resolved */
          /* The IPv4 address is embedded in a in6_addr structure,
           * so it need be copied, and delivered to resolve(). */
          memset(&scribdst, '\0', sizeof(scribdst));
          memcpy(&scribdst, &iptr->ip_dst, sizeof(struct in_addr));
          resolve(ap.af, &scribdst, NULL, 0);
          memset(&scribsrc, '\0', sizeof(scribsrc));
          memcpy(&scribsrc, &iptr->ip_src, sizeof(struct in_addr));
          resolve(ap.af, &scribsrc, NULL, 0);
          break;
      case 6:
          ap.protocol = ip6tr->ip6_nxt;
          /* Add the addresses to be resolved */
          resolve(ap.af, &ip6tr->ip6_dst, NULL, 0);
          resolve(ap.af, &ip6tr->ip6_src, NULL, 0);
      default:
          break;
    }


    if(hash_find(history, &ap, u_ht.void_pp) == HASH_STATUS_KEY_NOT_FOUND) {
        ht = history_create();
        hash_insert(history, &ap, ht);
    }

    /* Do accounting. */
    switch (IP_V(iptr)) {
      case 4:
          len = ntohs(iptr->ip_len);
          break;
      case 6:
          len = ntohs(ip6tr->ip6_plen) + 40;
      default:
          break;
    }

    /* Update record */
    ht->last_write = history_pos;
    if( ((IP_V(iptr) == 4) && (iptr->ip_src.s_addr == ap.src.s_addr))
       || ((IP_V(iptr) == 6) && !memcmp(&ip6tr->ip6_src, &ap.src6, sizeof(ap.src6))) )
    {
        ht->sent[history_pos] += len;
        ht->total_sent += len;
    }
    else {
        ht->recv[history_pos] += len;
        ht->total_recv += len;
    }

    if(direction == 0) {
        /* incoming */
        history_totals.recv[history_pos] += len;
        history_totals.total_recv += len;
    }
    else {
        history_totals.sent[history_pos] += len;
        history_totals.total_sent += len;
    }
    
}

static void handle_raw_packet(unsigned char* args, const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
    handle_ip_packet((struct ip*)packet, -1);
}

#ifdef DLT_PFLOG
static void handle_pflog_packet(unsigned char* args, const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
	register u_int length = pkthdr->len;
	u_int hdrlen;
	const struct pfloghdr *hdr;
	
	hdr = (struct pfloghdr *)packet;
	hdrlen = BPF_WORDALIGN(hdr->length);
	length -= hdrlen;
	packet += hdrlen;
	handle_ip_packet((struct ip*)packet, -1);
}
#endif

static void handle_null_packet(unsigned char* args, const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
    handle_ip_packet((struct ip*)(packet + 4), -1);
}

static void handle_llc_packet(const struct llc* llc, int dir) {

    struct ip* ip = (struct ip*)((void*)llc + sizeof(struct llc));

    /* Taken from tcpdump/print-llc.c */
    if(llc->ssap == LLCSAP_SNAP && llc->dsap == LLCSAP_SNAP
       && llc->llcui == LLC_UI) {
        u_int32_t orgcode;
        register u_short et;
        orgcode = EXTRACT_24BITS(&llc->llc_orgcode[0]);
        et = EXTRACT_16BITS(&llc->llc_ethertype[0]);
        switch(orgcode) {
          case OUI_ENCAP_ETHER:
          case OUI_CISCO_90:
            handle_ip_packet(ip, dir);
            break;
          case OUI_APPLETALK:
            if(et == ETHERTYPE_ATALK) {
              handle_ip_packet(ip, dir);
            }
            break;
          default:;
            /* Not a lot we can do */
        }
    }
}

static void handle_tokenring_packet(unsigned char* args, const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
    struct token_header *trp;
    int dir = -1;
    trp = (struct token_header *)packet;

    if(IS_SOURCE_ROUTED(trp)) {
      packet += RIF_LENGTH(trp);
    }
    packet += TOKEN_HDRLEN;

    if(memcmp(trp->token_shost, if_hw_addr, 6) == 0 ) {
      /* packet leaving this i/f */
      dir = 1;
    } 
        else if(memcmp(trp->token_dhost, if_hw_addr, 6) == 0 || memcmp("\xFF\xFF\xFF\xFF\xFF\xFF", trp->token_dhost, 6) == 0) {
      /* packet entering this i/f */
      dir = 0;
    }

    /* Only know how to deal with LLC encapsulated packets */
    if(FRAME_TYPE(trp) == TOKEN_FC_LLC) {
      handle_llc_packet((struct llc*)packet, dir);
    }
}

static void handle_ppp_packet(unsigned char* args, const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
	register u_int length = pkthdr->len;
	register u_int caplen = pkthdr->caplen;
	u_int proto;

	if (caplen < 2) 
        return;

	if(packet[0] == PPP_ADDRESS) {
		if (caplen < 4) 
            return;

		packet += 2;
		length -= 2;

		proto = EXTRACT_16BITS(packet);
		packet += 2;
		length -= 2;

        if(proto == PPP_IP || proto == ETHERTYPE_IP || proto == ETHERTYPE_IPV6) {
            handle_ip_packet((struct ip*)packet, -1);
        }
    }
}

#ifdef DLT_LINUX_SLL
static void handle_cooked_packet(unsigned char *args, const struct pcap_pkthdr * thdr, const unsigned char * packet)
{
    struct sll_header *sptr;
    int dir = -1;
    sptr = (struct sll_header *) packet;

    switch (ntohs(sptr->sll_pkttype))
    {
    case LINUX_SLL_HOST:
        /*entering this interface*/
	dir = 0;
	break;
    case LINUX_SLL_OUTGOING:
	/*leaving this interface */
	dir=1;
	break;
    }
    handle_ip_packet((struct ip*)(packet+SLL_HDR_LEN), dir);
}
#endif /* DLT_LINUX_SLL */

static void handle_eth_packet(unsigned char* args, const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
    struct ether_header *eptr;
    int ether_type;
    const unsigned char *payload;
    eptr = (struct ether_header*)packet;
    ether_type = ntohs(eptr->ether_type);
    payload = packet + sizeof(struct ether_header);

    tick(0);

    if(ether_type == ETHERTYPE_8021Q) {
	struct vlan_8021q_header* vptr;
	vptr = (struct vlan_8021q_header*)payload;
	ether_type = ntohs(vptr->ether_type);
        payload += sizeof(struct vlan_8021q_header);
    }

    if(ether_type == ETHERTYPE_IP || ether_type == ETHERTYPE_IPV6) {
        struct ip* iptr;
        int dir = -1;
        
        /*
         * Is a direction implied by the MAC addresses?
         */
        if(have_hw_addr && memcmp(eptr->ether_shost, if_hw_addr, 6) == 0 ) {
            /* packet leaving this i/f */
            dir = 1;
        }
        else if(have_hw_addr && memcmp(eptr->ether_dhost, if_hw_addr, 6) == 0 ) {
	    /* packet entering this i/f */
	    dir = 0;
	}
	else if (memcmp("\xFF\xFF\xFF\xFF\xFF\xFF", eptr->ether_dhost, 6) == 0) {
	  /* broadcast packet, count as incoming */
            dir = 0;
        }

        /* Distinguishing ip_hdr and ip6_hdr will be done later. */
        iptr = (struct ip*)(payload); /* alignment? */
        handle_ip_packet(iptr, dir);
    }
}

#ifdef DLT_IEEE802_11_RADIO
/*
 * Packets with a bonus radiotap header.
 * See http://www.gsp.com/cgi-bin/man.cgi?section=9&topic=ieee80211_radiotap
 */
static void handle_radiotap_packet(unsigned char* args, const struct pcap_pkthdr* pkthdr, const unsigned char* packet)
{
    /* 802.11 MAC header is = 34 bytes (not sure if that's universally true) */
    /* We could try harder to figure out hardware direction from the MAC header */
    handle_ip_packet((struct ip*)(packet + ((struct radiotap_header *)packet)->it_len + 34),-1);
}


#endif

/* set_filter_code:
 * Install some filter code. Returns NULL on success or an error message on
 * failure. */
char *set_filter_code(const char *filter) {
    char *x;
    if (filter) {
        x = xmalloc(strlen(filter) + sizeof "() and (ip or ip6)");
        sprintf(x, "(%s) and (ip or ip6)", filter);
    } else
        x = xstrdup("ip or ip6");
    if (pcap_compile(pd, &pcap_filter, x, 1, 0) == -1) {
        xfree(x);
        return pcap_geterr(pd);
    }
    xfree(x);
    if (pcap_setfilter(pd, &pcap_filter) == -1)
        return pcap_geterr(pd);
    else
        return NULL;
}



/*
 * packet_init:
 *
 * performs pcap initialisation, called before ui is initialised
 */
void packet_init() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *m;
    int s;
    int i;
    int dlt;
    int result;

#ifdef HAVE_DLPI
    result = get_addrs_dlpi(options.interface, if_hw_addr, &if_ip_addr);
#else
    result = get_addrs_ioctl(options.interface, if_hw_addr,
          &if_ip_addr, &if_ip6_addr);
#endif

    if (result < 0) {
      exit(1);
    }

    have_hw_addr = result & 0x01;
    have_ip_addr = result & 0x02;
    have_ip6_addr = result & 0x04;
    
    if(have_ip_addr) {
      fprintf(stderr, "IP address is: %s\n", inet_ntoa(if_ip_addr));
    }
    if(have_ip6_addr) {
       char ip6str[INET6_ADDRSTRLEN];

       ip6str[0] = '\0';
       inet_ntop(AF_INET6, &if_ip6_addr, ip6str, sizeof(ip6str));
       fprintf(stderr, "IPv6 address is: %s\n", ip6str);
    }

    if(have_hw_addr) {
      fprintf(stderr, "MAC address is:");
      for (i = 0; i < 6; ++i)
	fprintf(stderr, "%c%02x", i ? ':' : ' ', (unsigned int)if_hw_addr[i]);
      fprintf(stderr, "\n");
    }
    
    //    exit(0);
    resolver_initialise();

    pd = pcap_open_live(options.interface, CAPTURE_LENGTH, options.promiscuous, 1000, errbuf);
    // DEBUG: pd = pcap_open_offline("tcpdump.out", errbuf);
    if(pd == NULL) { 
        fprintf(stderr, "pcap_open_live(%s): %s\n", options.interface, errbuf); 
        exit(1);
    }
    dlt = pcap_datalink(pd);
    if(dlt == DLT_EN10MB) {
        packet_handler = handle_eth_packet;
    }
#ifdef DLT_PFLOG
    else if (dlt == DLT_PFLOG) {
		packet_handler = handle_pflog_packet;
    }
#endif
    else if(dlt == DLT_RAW) {
        packet_handler = handle_raw_packet;
    } 
    else if(dlt == DLT_NULL) {
        packet_handler = handle_null_packet;
    } 
#ifdef DLT_LOOP
    else if(dlt == DLT_LOOP) {
        packet_handler = handle_null_packet;
    }
#endif
#ifdef DLT_IEEE802_11_RADIO
    else if(dlt == DLT_IEEE802_11_RADIO) {
        packet_handler = handle_radiotap_packet;
    }
#endif
    else if(dlt == DLT_IEEE802) {
        packet_handler = handle_tokenring_packet;
    }
    else if(dlt == DLT_PPP) {
        packet_handler = handle_ppp_packet;
    }
/* 
 * SLL support not available in older libpcaps
 */
#ifdef DLT_LINUX_SLL
    else if(dlt == DLT_LINUX_SLL) {
      packet_handler = handle_cooked_packet;
    }
#endif
    else {
        fprintf(stderr, "Unsupported datalink type: %d\n"
                "Please email pdw@ex-parrot.com, quoting the datalink type and what you were\n"
                "trying to do at the time\n.", dlt);
        exit(1);
    }

    if ((m = set_filter_code(options.filtercode))) {
        fprintf(stderr, "set_filter_code: %s\n", m);
        exit(1);
        return;
    }
}

/* packet_loop:
 * Worker function for packet capture thread. */
void packet_loop(void* ptr) {
    pcap_loop(pd,-1,(pcap_handler)packet_handler,NULL);
}


/* main:
 * Entry point. See usage(). */
int main(int argc, char **argv) {
    pthread_t thread;
    struct sigaction sa = {};

    setlocale(LC_ALL, "");

    /* TODO: tidy this up */
    /* read command line options and config file */   
    config_init();
    options_set_defaults();
    options_read_args(argc, argv);
    /* If a config was explicitly specified, whinge if it can't be found */
    read_config(options.config_file, options.config_file_specified);
    options_make();
    
    sa.sa_handler = finish;
    sigaction(SIGINT, &sa, NULL);

    pthread_mutex_init(&tick_mutex, NULL);

    packet_init();

    init_history();

    ui_init();

    pthread_create(&thread, NULL, (void*)&packet_loop, NULL);

    ui_loop();

    pthread_cancel(thread);

    ui_finish();
    
    return 0;
}
