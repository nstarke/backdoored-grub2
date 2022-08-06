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

#ifndef disknet_grub_net_TCP_HEADER
#define disknet_grub_net_TCP_HEADER	1
#include <grub/types.h>
#include "net.h"

struct disknet_grub_net_tcp_socket;
typedef struct disknet_grub_net_tcp_socket *disknet_grub_net_tcp_socket_t;

struct disknet_grub_net_tcp_listen;
typedef struct disknet_grub_net_tcp_listen *disknet_grub_net_tcp_listen_t;

disknet_grub_net_tcp_socket_t
disknet_grub_net_tcp_open (char *server,
		   grub_uint16_t out_port,
		   grub_err_t (*recv_hook) (disknet_grub_net_tcp_socket_t sock,
					    struct disknet_grub_net_buff *nb,
					    void *data),
		   void (*error_hook) (disknet_grub_net_tcp_socket_t sock,
				       void *data),
		   void (*fin_hook) (disknet_grub_net_tcp_socket_t sock,
				     void *data),
		   void *hook_data);

disknet_grub_net_tcp_listen_t
disknet_grub_net_tcp_listen (grub_uint16_t port,
		     const struct disknet_grub_net_network_level_interface *inf,
		     grub_err_t (*listen_hook) (disknet_grub_net_tcp_listen_t listen,
						disknet_grub_net_tcp_socket_t sock,
						void *data),
		     void *hook_data);

void
disknet_grub_net_tcp_stop_listen (disknet_grub_net_tcp_listen_t listen);

grub_err_t
disknet_grub_net_send_tcp_packet (const disknet_grub_net_tcp_socket_t socket,
			  struct disknet_grub_net_buff *nb,
			  int push);

enum
  {
    disknet_grub_net_TCP_CONTINUE_RECEIVING,
    disknet_grub_net_TCP_DISCARD,
    disknet_grub_net_TCP_ABORT
  };

void
disknet_grub_net_tcp_close (disknet_grub_net_tcp_socket_t sock, int discard_received);

grub_err_t
disknet_grub_net_tcp_accept (disknet_grub_net_tcp_socket_t sock,
		     grub_err_t (*recv_hook) (disknet_grub_net_tcp_socket_t sock,
					      struct disknet_grub_net_buff *nb,
					      void *data),
		     void (*error_hook) (disknet_grub_net_tcp_socket_t sock,
					 void *data),
		     void (*fin_hook) (disknet_grub_net_tcp_socket_t sock,
				       void *data),
		     void *hook_data);

void
disknet_grub_net_tcp_stall (disknet_grub_net_tcp_socket_t sock);

void
disknet_grub_net_tcp_unstall (disknet_grub_net_tcp_socket_t sock);

#endif
