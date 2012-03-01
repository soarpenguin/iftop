/* hash table */

#include <stdio.h>
#include <stdlib.h>
#include "addr_hash.h"
#include "hash.h"
#include "iftop.h"

#define hash_table_size 256

int compare(void* a, void* b) {
    addr_pair* aa = (addr_pair*)a;
    addr_pair* bb = (addr_pair*)b;

    if (aa->af != bb->af)
        return 0;

    if (aa->af == AF_INET6) {
       return (IN6_ARE_ADDR_EQUAL(&aa->src6, &bb->src6)
               && aa->src_port == bb->src_port
               && IN6_ARE_ADDR_EQUAL(&aa->dst6, &bb->dst6)
               && aa->dst_port == bb->dst_port
               && aa->protocol == bb->protocol);
    }

    /* AF_INET or unknown. */
    return (aa->src.s_addr == bb->src.s_addr 
            && aa->src_port == bb->src_port
            && aa->dst.s_addr == bb->dst.s_addr
            && aa->dst_port == bb->dst_port
            && aa->protocol == bb->protocol);
}

static int __inline__ hash_uint32(uint32_t n) {
    return ((n & 0x000000FF)
            + ((n & 0x0000FF00) >> 8)
            + ((n & 0x00FF0000) >> 16)
            + ((n & 0xFF000000) >> 24));
}

int hash(void* key) {
    int hash;
    addr_pair* ap = (addr_pair*)key;

    if (ap->af == AF_INET6) {
        uint32_t* addr6 = (uint32_t*)ap->src6.s6_addr;

        hash = ( hash_uint32(addr6[0])
                + hash_uint32(addr6[1])
                + hash_uint32(addr6[2])
                + hash_uint32(addr6[3])
                + ap->src_port) % 0xFF;

        addr6 = (uint32_t*)ap->dst6.s6_addr;
        hash = ( hash + hash_uint32(addr6[0])
                + hash_uint32(addr6[1])
                + hash_uint32(addr6[2])
                + hash_uint32(addr6[3])
                + ap->dst_port) % 0xFF;
    } else {
        in_addr_t addr = ap->src.s_addr;

        hash = ( hash_uint32(addr)
                + ap->src_port) % 0xFF;

        addr = ap->dst.s_addr;
        hash = ( hash + hash_uint32(addr)
                + ap->dst_port) % 0xFF;
    }

    return hash;
}

void* copy_key(void* orig) {
    addr_pair* copy;
    copy = xmalloc(sizeof *copy);
    *copy = *(addr_pair*)orig;
    return copy;
}

void delete_key(void* key) {
    free(key);
}

/*
 * Allocate and return a hash
 */
hash_type* addr_hash_create() {
    hash_type* hash_table;
    //XXX: hash_table is a hash_type*, it's store a hash_node_type**
	// initialise the hash_table like beside will waster 255 hash_type memory 
	// hash_table = xcalloc(hash_table_size, sizeof *hash_table);
    hash_table = xcalloc(1, sizeof *hash_table);
    hash_table->size = hash_table_size;
    hash_table->compare = &compare;
    hash_table->hash = &hash;
    hash_table->delete_key = &delete_key;
    hash_table->copy_key = &copy_key;
    hash_initialise(hash_table);
    return hash_table;
}

