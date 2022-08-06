/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010,2011  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef disknet_grub_net_IP_HEADER
#define disknet_grub_net_IP_HEADER	1
#include <grub/misc.h>
#include "net.h"

typedef enum disknet_grub_net_ip_protocol
  {
    disknet_grub_net_IP_ICMP = 1,
    disknet_grub_net_IP_TCP = 6,
    disknet_grub_net_IP_UDP = 17,
    disknet_grub_net_IP_ICMPV6 = 58
  } disknet_grub_net_ip_protocol_t;
#define disknet_grub_net_IP_BROADCAST    0xFFFFFFFF

static inline grub_uint64_t
disknet_grub_net_ipv6_get_id (const disknet_grub_net_link_level_address_t *addr)
{
  return grub_cpu_to_be64 (((grub_uint64_t) (addr->mac[0] ^ 2) << 56)
			   | ((grub_uint64_t) addr->mac[1] << 48)
			   | ((grub_uint64_t) addr->mac[2] << 40)
			   | 0xfffe000000ULL
			   | ((grub_uint64_t) addr->mac[3] << 16)
			   | ((grub_uint64_t) addr->mac[4] << 8)
			   | ((grub_uint64_t) addr->mac[5]));
}

grub_uint16_t disknet_grub_net_ip_chksum(void *ipv, grub_size_t len);

grub_err_t
disknet_grub_net_recv_ip_packets (struct disknet_grub_net_buff *nb,
			  struct disknet_grub_net_card *card,
			  const disknet_grub_net_link_level_address_t *hwaddress,
			  const disknet_grub_net_link_level_address_t *src_hwaddress,
                          grub_uint16_t *vlantag);

grub_err_t
disknet_grub_net_send_ip_packet (struct disknet_grub_net_network_level_interface *inf,
			 const disknet_grub_net_network_level_address_t *target,
			 const disknet_grub_net_link_level_address_t *ll_target_addr,
			 struct disknet_grub_net_buff *nb,
			 disknet_grub_net_ip_protocol_t proto);

grub_err_t
disknet_grub_net_recv_icmp_packet (struct disknet_grub_net_buff *nb,
			   struct disknet_grub_net_network_level_interface *inf,
			   const disknet_grub_net_link_level_address_t *ll_src,
			   const disknet_grub_net_network_level_address_t *src);
grub_err_t
disknet_grub_net_recv_icmp6_packet (struct disknet_grub_net_buff *nb,
			    struct disknet_grub_net_card *card,
			    struct disknet_grub_net_network_level_interface *inf,
			    const disknet_grub_net_link_level_address_t *ll_src,
			    const disknet_grub_net_network_level_address_t *source,
			    const disknet_grub_net_network_level_address_t *dest,
			    grub_uint8_t ttl);
grub_err_t
disknet_grub_net_recv_udp_packet (struct disknet_grub_net_buff *nb,
			  struct disknet_grub_net_network_level_interface *inf,
			  const disknet_grub_net_network_level_address_t *src);
grub_err_t
disknet_grub_net_recv_tcp_packet (struct disknet_grub_net_buff *nb,
			  struct disknet_grub_net_network_level_interface *inf,
			  const disknet_grub_net_network_level_address_t *source);

grub_uint16_t
disknet_grub_net_ip_transport_checksum (struct disknet_grub_net_buff *nb,
				grub_uint16_t proto,
				const disknet_grub_net_network_level_address_t *src,
				const disknet_grub_net_network_level_address_t *dst);

struct disknet_grub_net_network_level_interface *
disknet_grub_net_ipv6_get_link_local (struct disknet_grub_net_card *card,
			      const disknet_grub_net_link_level_address_t *hwaddr);
grub_err_t
disknet_grub_net_icmp6_send_request (struct disknet_grub_net_network_level_interface *inf,
			     const disknet_grub_net_network_level_address_t *proto_addr);

grub_err_t
disknet_grub_net_icmp6_send_router_solicit (struct disknet_grub_net_network_level_interface *inf);
#endif
