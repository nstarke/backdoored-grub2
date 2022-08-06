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

#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/env.h>
#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include "netbuff.h"
#include "net.h"
#include <grub/time.h>
#include "arp.h"

#define LLCADDRMASK 0x7f

struct disknet_etherhdr
{
  grub_uint8_t dst[6];
  grub_uint8_t src[6];
  grub_uint16_t type;
} GRUB_PACKED;

struct disknet_llchdr
{
  grub_uint8_t dsap;
  grub_uint8_t ssap;
  grub_uint8_t ctrl;
} GRUB_PACKED;

struct disknet_snaphdr
{
  grub_uint8_t oui[3];
  grub_uint16_t type;
} GRUB_PACKED;

grub_err_t
disknet_send_ethernet_packet (struct disknet_grub_net_network_level_interface *inf,
		      struct disknet_grub_net_buff *nb,
		      disknet_grub_net_link_level_address_t target_addr,
		      disknet_grub_net_ethertype_t ethertype)
{
  struct disknet_etherhdr *eth;
  grub_err_t err;
  grub_uint8_t disknet_etherhdr_size;
  grub_uint16_t vlantag_id = grub_cpu_to_be16_compile_time (VLANTAG_IDENTIFIER);

  disknet_etherhdr_size = sizeof (*eth);
  COMPILE_TIME_ASSERT (sizeof (*eth) + 4 < disknet_grub_net_MAX_LINK_HEADER_SIZE);

  /* Increase ethernet header in case of vlantag */
  if (inf->vlantag != 0)
    disknet_etherhdr_size += 4;

  err = disknet_grub_netbuff_push (nb, disknet_etherhdr_size);
  if (err)
    return err;
  eth = (struct disknet_etherhdr *) nb->data;
  grub_memcpy (eth->dst, target_addr.mac, 6);
  grub_memcpy (eth->src, inf->hwaddress.mac, 6);

  eth->type = grub_cpu_to_be16 (ethertype);
  if (!inf->card->opened)
    {
      err = GRUB_ERR_NONE;
      if (inf->card->driver->open)
	err = inf->card->driver->open (inf->card);
      if (err)
	return err;
      inf->card->opened = 1;
    }

  /* Check and add a vlan-tag if needed. */
  if (inf->vlantag != 0)
    {
      /* Move eth type to the right */
      grub_memcpy ((char *) nb->data + disknet_etherhdr_size - 2,
                   (char *) nb->data + disknet_etherhdr_size - 6, 2);

      /* Add the tag in the middle */
      grub_uint16_t vlan = grub_cpu_to_be16 (inf->vlantag);
      grub_memcpy ((char *) nb->data + disknet_etherhdr_size - 6, &vlantag_id, 2);
      grub_memcpy ((char *) nb->data + disknet_etherhdr_size - 4, &vlan, 2);
    }

  return inf->card->driver->send (inf->card, nb);
}

grub_err_t
disknet_grub_net_recv_ethernet_packet (struct disknet_grub_net_buff *nb,
			       struct disknet_grub_net_card *card)
{
  struct disknet_etherhdr *eth;
  struct disknet_llchdr *llch;
  struct disknet_snaphdr *snaph;
  disknet_grub_net_ethertype_t type;
  disknet_grub_net_link_level_address_t hwaddress;
  disknet_grub_net_link_level_address_t src_hwaddress;
  grub_err_t err;
  grub_uint8_t disknet_etherhdr_size = sizeof (*eth);
  grub_uint16_t vlantag = 0;

  /* Check if a vlan-tag is present. If so, the ethernet header is 4 bytes */
  /* longer than the original one. The vlantag id is extracted and the header */
  /* is reseted to the original size. */
  if (grub_get_unaligned16 (nb->data + disknet_etherhdr_size - 2) == grub_cpu_to_be16_compile_time (VLANTAG_IDENTIFIER))
    {
      vlantag = grub_be_to_cpu16 (grub_get_unaligned16 (nb->data + disknet_etherhdr_size));
      disknet_etherhdr_size += 4;
      /* Move eth type to the original position */
      grub_memcpy((char *) nb->data + disknet_etherhdr_size - 6,
                  (char *) nb->data + disknet_etherhdr_size - 2, 2);
    }
  eth = (struct disknet_etherhdr *) nb->data;
  type = grub_be_to_cpu16 (eth->type);
  err = disknet_grub_netbuff_pull (nb, disknet_etherhdr_size);
  if (err)
    return err;
  if (type <= 1500)
    {
      llch = (struct disknet_llchdr *) nb->data;
      type = llch->dsap & LLCADDRMASK;

      if (llch->dsap == 0xaa && llch->ssap == 0xaa && llch->ctrl == 0x3)
	{
	  err = disknet_grub_netbuff_pull (nb, sizeof (*llch));
	  if (err)
	    return err;
	  snaph = (struct disknet_snaphdr *) nb->data;
	  type = snaph->type;
	}
    }
  hwaddress.type = disknet_grub_net_LINK_LEVEL_PROTOCOL_ETHERNET;
  grub_memcpy (hwaddress.mac, eth->dst, sizeof (hwaddress.mac));
  src_hwaddress.type = disknet_grub_net_LINK_LEVEL_PROTOCOL_ETHERNET;
  grub_memcpy (src_hwaddress.mac, eth->src, sizeof (src_hwaddress.mac));
  switch (type)
    {
      /* ARP packet. */
    case disknet_grub_net_ETHERTYPE_ARP:
      disknet_grub_net_arp_receive (nb, card, &vlantag);
      disknet_grub_netbuff_free (nb);
      return GRUB_ERR_NONE;
      /* IP packet.  */
    case disknet_grub_net_ETHERTYPE_IP:
    case disknet_grub_net_ETHERTYPE_IP6:
      return disknet_grub_net_recv_ip_packets (nb, card, &hwaddress, &src_hwaddress,
                                       &vlantag);
    }
  disknet_grub_netbuff_free (nb);
  return GRUB_ERR_NONE;
}
