/*
 * addrs_ioctl.c:
 *
 * Provides the get_addrs_ioctl() function for use on systems that
 * support a simple socket ioctl for acquiring low-level ethernet
 * information about interfaces.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#if defined __FreeBSD__ || defined __OpenBSD__ || defined __APPLE__ \
      || ( defined __GNUC__ && ! defined __linux__ )
#include <sys/param.h>
#include <sys/sysctl.h>
#include <net/if_dl.h>
#endif

#ifdef USE_GETIFADDRS
#include <ifaddrs.h>
#endif

#include "iftop.h"

/*
 * This function identifies the IP address and ethernet address for the requested
 * interface
 *
 * This function returns -1 on catastrophic failure, or a bitwise OR of the
 * following values:
 *
 * 1 - Was able to get the ethernet address
 * 2 - Was able to get the IP address
 *
 * This function should return 3 if all information was found
 */

int
get_addrs_ioctl(char *interface, char if_hw_addr[], struct in_addr *if_ip_addr, struct in6_addr *if_ip6_addr)
{
  int s;
  struct ifreq ifr = {};
  int got_hw_addr = 0;
  int got_ip_addr = 0;
  int got_ip6_addr = 0;
#ifdef USE_GETIFADDRS
  struct ifaddrs *ifa, *ifas;
#endif

  /* -- */

  s = socket(AF_INET, SOCK_DGRAM, 0); /* any sort of IP socket will do */

  if (s == -1) {
    perror("socket");
    return -1;
  }

  fprintf(stderr,"interface: %s\n", interface);

  memset(if_hw_addr, 0, 6);
  strncpy(ifr.ifr_name, interface, IFNAMSIZ);

#ifdef SIOCGIFHWADDR
  if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
    fprintf(stderr, "Error getting hardware address for interface: %s\n", interface); 
    perror("ioctl(SIOCGIFHWADDR)");
  }
  else {
    memcpy(if_hw_addr, ifr.ifr_hwaddr.sa_data, 6);
    got_hw_addr = 1;
  }
#else
#if defined __FreeBSD__ || defined __OpenBSD__ || defined __APPLE__ \
      || ( defined __GNUC__ && ! defined __linux__ )
  {
    int sysctlparam[6] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST, 0};
    size_t needed = 0;
    char *buf = NULL;
    struct if_msghdr *msghdr = NULL;
    sysctlparam[5] = if_nametoindex(interface);
    if (sysctlparam[5] == 0) {
      fprintf(stderr, "Error getting hardware address for interface: %s\n", interface);
      goto ENDHWADDR;
    }
    if (sysctl(sysctlparam, 6, NULL, &needed, NULL, 0) < 0) {
      fprintf(stderr, "Error getting hardware address for interface: %s\n", interface);
      goto ENDHWADDR;
    }
    if ((buf = malloc(needed)) == NULL) {
      fprintf(stderr, "Error getting hardware address for interface: %s\n", interface);
      goto ENDHWADDR;
    }
    if (sysctl(sysctlparam, 6, buf, &needed, NULL, 0) < 0) {
      fprintf(stderr, "Error getting hardware address for interface: %s\n", interface);
      free(buf);
      goto ENDHWADDR;
    }
    msghdr = (struct if_msghdr *) buf;
    memcpy(if_hw_addr, LLADDR((struct sockaddr_dl *)(buf + sizeof(struct if_msghdr) - sizeof(struct if_data) + sizeof(struct if_data))), 6);
    free(buf);
    got_hw_addr = 1;

  ENDHWADDR:
    1; /* compiler whines if there is a label at the end of a block...*/
  }
#else
  fprintf(stderr, "Cannot obtain hardware address on this platform\n");
#endif
#endif
  
  /* Get the IP address of the interface */
#ifdef USE_GETIFADDRS
  if (getifaddrs(&ifas) == -1) {
    fprintf(stderr, "Unable to get IP address for interface: %s\n", interface); 
    perror("getifaddrs()");
  }
  else {
     for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
        if (got_ip_addr && got_ip6_addr)
           break; /* Search is already complete. */

        if (strcmp(ifa->ifa_name, interface))
           continue; /* Not our interface. */

        if (ifa->ifa_addr == NULL)
           continue; /* Skip NULL interface address. */

        if ( (ifa->ifa_addr->sa_family != AF_INET)
              && (ifa->ifa_addr->sa_family != AF_INET6) )
           continue; /* AF_PACKET is beyond our scope. */

        if ( (ifa->ifa_addr->sa_family == AF_INET)
              && !got_ip_addr ) {
           got_ip_addr = 2;
           memcpy(if_ip_addr,
                 &(((struct sockaddr_in *) ifa->ifa_addr)->sin_addr),
                 sizeof(*if_ip_addr));
           continue;
        }
        /* Must be a IPv6 address at this point. */
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) ifa->ifa_addr;

        if ( IN6_IS_ADDR_LINKLOCAL(&(sa6->sin6_addr))
              || IN6_IS_ADDR_SITELOCAL(&(sa6->sin6_addr)) )
           continue;

        /* A useful IPv6 address. */
        memcpy(if_ip6_addr, &(sa6->sin6_addr), sizeof(*if_ip6_addr));
        got_ip6_addr = 4;
     }
     freeifaddrs(ifas);
  } /* getifaddrs() */
#elif defined(SIOCGIFADDR)
  (*(struct sockaddr_in *) &ifr.ifr_addr).sin_family = AF_INET;
  if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
    fprintf(stderr, "Unable to get IP address for interface: %s\n", interface); 
    perror("ioctl(SIOCGIFADDR)");
  }
  else {
    memcpy(if_ip_addr, &((*(struct sockaddr_in *) &ifr.ifr_addr).sin_addr), sizeof(struct in_addr));
    got_ip_addr = 2;
  }
#else
  fprintf(stderr, "Cannot obtain IP address on this platform\n");
#endif
  
  close(s);

  return got_hw_addr + got_ip_addr + got_ip6_addr;
}
