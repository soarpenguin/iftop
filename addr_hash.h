/*
 * addr_hash.h:
 *
 */

#ifndef __ADDR_HASH_H_ /* include guard */
#define __ADDR_HASH_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "hash.h"

typedef struct {
    int af;
    unsigned short int protocol;
    unsigned short int src_port;
    union {
        struct in_addr src;
        struct in6_addr src6;
    };
    unsigned short int dst_port;
    union {
        struct in_addr dst;
        struct in6_addr dst6;
    };
} addr_pair;

typedef addr_pair key_type;      /* index into hash table */

hash_type* addr_hash_create(void);

#endif /* __ADDR_HASH_H_ */
