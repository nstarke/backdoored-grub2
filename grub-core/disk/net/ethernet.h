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

#ifndef disknet_grub_net_ETHERNET_HEADER
#define disknet_grub_net_ETHERNET_HEADER	1
#include <grub/types.h>
#include "net.h"

/* IANA Ethertype */
typedef enum
  {
    disknet_grub_net_ETHERTYPE_IP = 0x0800,
    disknet_grub_net_ETHERTYPE_ARP = 0x0806,
    disknet_grub_net_ETHERTYPE_IP6 = 0x86DD,
  } disknet_grub_net_ethertype_t;

grub_err_t
disknet_send_ethernet_packet (struct disknet_grub_net_network_level_interface *inf,
		      struct disknet_grub_net_buff *nb,
		      disknet_grub_net_link_level_address_t target_addr,
		      disknet_grub_net_ethertype_t ethertype);
grub_err_t
disknet_grub_net_recv_ethernet_packet (struct disknet_grub_net_buff *nb,
			       struct disknet_grub_net_card *card);

#endif
