/* hash table */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ns_hash.h"
#include "hash.h"
#include "iftop.h"

#define hash_table_size 256

int ns_hash_compare(void* a, void* b) {
    struct in6_addr* aa = (struct in6_addr*)a;
    struct in6_addr* bb = (struct in6_addr*)b;
    return IN6_ARE_ADDR_EQUAL(aa, bb);
}

static int __inline__ hash_uint32(uint32_t n) {
    return ((n & 0x000000FF)
            + ((n & 0x0000FF00) >> 8)
            + ((n & 0x00FF0000) >> 16)
            + ((n & 0xFF000000) >> 24));
}

int ns_hash_hash(void* key) {
    int hash;
    uint32_t* addr6 = (uint32_t*)((struct in6_addr *) key)->s6_addr;

    hash = ( hash_uint32(addr6[0])
            + hash_uint32(addr6[1])
            + hash_uint32(addr6[2])
            + hash_uint32(addr6[3])) % 0xFF;

    return hash;
}

void* ns_hash_copy_key(void* orig) {
    struct in6_addr* copy;

    copy = xmalloc(sizeof *copy);
    memcpy(copy, orig, sizeof *copy);

    return copy;
}

void ns_hash_delete_key(void* key) {
    free(key);
}

/*
 * Allocate and return a hash
 */
hash_type* ns_hash_create() {
    hash_type* hash_table;
    //XXX: hash_table is a hash_type*, it's store a hash_node_type**
	// initialise the hash_table like beside will waster 255 hash_type memory 
	// hash_table = xcalloc(hash_table_size, sizeof *hash_table);
    hash_table = xcalloc(1, sizeof *hash_table);
    hash_table->size = hash_table_size;
    hash_table->compare = &ns_hash_compare;
    hash_table->hash = &ns_hash_hash;
    hash_table->delete_key = &ns_hash_delete_key;
    hash_table->copy_key = &ns_hash_copy_key;
    hash_initialise(hash_table);
    return hash_table;
}

