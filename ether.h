#ifndef __ETHER_H_
#define __ETHER_H_

#define	ETHERTYPE_PUP		0x0200   
#define	ETHERTYPE_IP		0x0800
#define	ETHERTYPE_ARP		0x0806
#define	ETHERTYPE_REVARP	0x8035

#define	ETHER_ADDR_LEN		6

struct	ether_header {
	u_int8_t	ether_dhost[ETHER_ADDR_LEN];
	u_int8_t	ether_shost[ETHER_ADDR_LEN];
	u_int16_t	ether_type;
} __attribute__((packed));


struct vlan_8021q_header {
	u_int16_t	priority_cfi_vid;
	u_int16_t	ether_type;
};

/*
 * http://www.gsp.com/cgi-bin/man.cgi?section=9&topic=ieee80211_radiotap
 */
struct radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((packed));

#endif 
