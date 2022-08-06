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

#ifndef disknet_grub_net_UDP_HEADER
#define disknet_grub_net_UDP_HEADER	1
#include <grub/types.h>
#include "net.h"

struct disknet_udphdr
{
  grub_uint16_t src;
  grub_uint16_t dst;
  grub_uint16_t len;
  grub_uint16_t chksum;
} GRUB_PACKED;

struct disknet_grub_net_udp_socket;
typedef struct disknet_grub_net_udp_socket *disknet_grub_net_udp_socket_t;

disknet_grub_net_udp_socket_t
disknet_grub_net_udp_open (disknet_grub_net_network_level_address_t addr,
		   grub_uint16_t out_port,
		   grub_err_t (*recv_hook) (disknet_grub_net_udp_socket_t sock,
					    struct disknet_grub_net_buff *nb,
					    void *data),
		   void *recv_hook_data);

void
disknet_grub_net_udp_close (disknet_grub_net_udp_socket_t sock);

grub_err_t
disknet_grub_net_send_udp_packet (const disknet_grub_net_udp_socket_t socket,
			  struct disknet_grub_net_buff *nb);


#endif
