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

#include "ip.h"
#include <grub/misc.h>
#include "arp.h"
#include "udp.h"
#include "ethernet.h"
#include "net.h"
#include "netbuff.h"
#include <grub/mm.h>
#include <grub/priority_queue.h>
#include <grub/time.h>

struct disknet_iphdr {
  grub_uint8_t verhdrlen;
  grub_uint8_t service;
  grub_uint16_t len;
  grub_uint16_t ident;
  grub_uint16_t frags;
  grub_uint8_t ttl;
  grub_uint8_t protocol;
  grub_uint16_t chksum;
  grub_uint32_t src;
  grub_uint32_t dest;
} GRUB_PACKED ;

enum
{
  DONT_FRAGMENT =  0x4000,
  MORE_FRAGMENTS = 0x2000,
  OFFSET_MASK =    0x1fff
};

typedef grub_uint64_t ip6addr[2];

struct ip6hdr {
  grub_uint32_t version_class_flow;
  grub_uint16_t len;
  grub_uint8_t protocol;
  grub_uint8_t ttl;
  ip6addr src;
  ip6addr dest;
} GRUB_PACKED ;

static int
cmp (const void *a__, const void *b__)
{
  struct disknet_grub_net_buff *a_ = *(struct disknet_grub_net_buff **) a__;
  struct disknet_grub_net_buff *b_ = *(struct disknet_grub_net_buff **) b__;
  struct disknet_iphdr *a = (struct disknet_iphdr *) a_->data;
  struct disknet_iphdr *b = (struct disknet_iphdr *) b_->data;
  /* We want the first elements to be on top.  */
  if ((grub_be_to_cpu16 (a->frags) & OFFSET_MASK)
      < (grub_be_to_cpu16 (b->frags) & OFFSET_MASK))
    return +1;
  if ((grub_be_to_cpu16 (a->frags) & OFFSET_MASK)
      > (grub_be_to_cpu16 (b->frags) & OFFSET_MASK))
    return -1;
  return 0;
}

struct reassemble
{
  struct reassemble *next;
  grub_uint32_t source;
  grub_uint32_t dest;
  grub_uint16_t id;
  grub_uint8_t proto;
  grub_uint64_t last_time;
  grub_priority_queue_t pq;
  struct disknet_grub_net_buff *asm_netbuff;
  grub_size_t total_len;
  grub_size_t cur_ptr;
  grub_uint8_t ttl;
};

static struct reassemble *reassembles;

grub_uint16_t
disknet_grub_net_ip_chksum (void *ipv, grub_size_t len)
{
  grub_uint16_t *ip = (grub_uint16_t *) ipv;
  grub_uint32_t sum = 0;

  for (; len >= 2; len -= 2)
    {
      sum += grub_be_to_cpu16 (grub_get_unaligned16 (ip++));
      if (sum > 0xFFFF)
	sum -= 0xFFFF;
    }
  if (len)
    {
      sum += *((grub_uint8_t *) ip) << 8;
      if (sum > 0xFFFF)
	sum -= 0xFFFF;
    }

  if (sum >= 0xFFFF)
    sum -= 0xFFFF;

  return grub_cpu_to_be16 ((~sum) & 0x0000FFFF);
}

static int id = 0x2400;

static grub_err_t
send_fragmented (struct disknet_grub_net_network_level_interface * inf,
		 const disknet_grub_net_network_level_address_t * target,
		 struct disknet_grub_net_buff * nb,
		 disknet_grub_net_ip_protocol_t proto,
		 disknet_grub_net_link_level_address_t ll_target_addr)
{
  grub_size_t off = 0;
  grub_size_t fraglen;
  grub_err_t err;

  fraglen = (inf->card->mtu - sizeof (struct disknet_iphdr)) & ~7;
  id++;

  while (nb->tail - nb->data)
    {
      grub_size_t len = fraglen;
      struct disknet_grub_net_buff *nb2;
      struct disknet_iphdr *iph;

      if ((grub_ssize_t) len > nb->tail - nb->data)
	len = nb->tail - nb->data;
      nb2 = disknet_grub_netbuff_alloc (fraglen + sizeof (struct disknet_iphdr)
				+ disknet_grub_net_MAX_LINK_HEADER_SIZE);
      if (!nb2)
	return grub_errno;
      err = disknet_grub_netbuff_reserve (nb2, disknet_grub_net_MAX_LINK_HEADER_SIZE);
      if (err)
	return err;
      err = disknet_grub_netbuff_put (nb2, sizeof (struct disknet_iphdr));
      if (err)
	return err;

      iph = (struct disknet_iphdr *) nb2->data;
      iph->verhdrlen = ((4 << 4) | 5);
      iph->service = 0;
      iph->len = grub_cpu_to_be16 (len + sizeof (struct disknet_iphdr));
      iph->ident = grub_cpu_to_be16 (id);
      iph->frags = grub_cpu_to_be16 (off | (((grub_ssize_t) len
					     == nb->tail - nb->data)
					    ? 0 : MORE_FRAGMENTS));
      iph->ttl = 0xff;
      iph->protocol = proto;
      iph->src = inf->address.ipv4;
      iph->dest = target->ipv4;
      off += len / 8;

      iph->chksum = 0;
      iph->chksum = disknet_grub_net_ip_chksum ((void *) nb2->data, sizeof (*iph));
      err = disknet_grub_netbuff_put (nb2, len);
      if (err)
	return err;
      grub_memcpy (iph + 1, nb->data, len);
      err = disknet_grub_netbuff_pull (nb, len);
      if (err)
	return err;
      err = disknet_send_ethernet_packet (inf, nb2, ll_target_addr,
				  disknet_grub_net_ETHERTYPE_IP);
      if (err)
	return err;
    }
  return GRUB_ERR_NONE;
}

static grub_err_t
disknet_grub_net_send_ip4_packet (struct disknet_grub_net_network_level_interface *inf,
			  const disknet_grub_net_network_level_address_t *target,
			  const disknet_grub_net_link_level_address_t *ll_target_addr,
			  struct disknet_grub_net_buff *nb,
			  disknet_grub_net_ip_protocol_t proto)
{
  struct disknet_iphdr *iph;
  grub_err_t err;
  COMPILE_TIME_ASSERT (disknet_grub_net_OUR_IPV4_HEADER_SIZE == sizeof (*iph));
  if (nb->tail - nb->data + sizeof (struct disknet_iphdr) > inf->card->mtu){
    return send_fragmented (inf, target, nb, proto, *ll_target_addr);
  }
  err = disknet_grub_netbuff_push (nb, sizeof (*iph));
  if (err)
    return err;
  iph = (struct disknet_iphdr *) nb->data;
  iph->verhdrlen = ((4 << 4) | 5);
  iph->service = 0;
  iph->len = grub_cpu_to_be16 (nb->tail - nb->data);
  iph->ident = grub_cpu_to_be16 (++id);
  iph->frags = 0;
  iph->ttl = 0xff;
  iph->protocol = proto;
  iph->src = inf->address.ipv4;
  iph->dest = target->ipv4;

  iph->chksum = 0;
  iph->chksum = disknet_grub_net_ip_chksum ((void *) nb->data, sizeof (*iph));
  return disknet_send_ethernet_packet (inf, nb, *ll_target_addr,
			       disknet_grub_net_ETHERTYPE_IP);
}

static grub_err_t
disknet_handle_dgram (struct disknet_grub_net_buff *nb,
	      struct disknet_grub_net_card *card,
	      const disknet_grub_net_link_level_address_t *source_hwaddress,
	      const disknet_grub_net_link_level_address_t *hwaddress,
	      disknet_grub_net_ip_protocol_t proto,
	      const disknet_grub_net_network_level_address_t *source,
	      const disknet_grub_net_network_level_address_t *dest,
              grub_uint16_t *vlantag,
	      grub_uint8_t ttl)
{
  struct disknet_grub_net_network_level_interface *inf = NULL;
  grub_err_t err;
  int multicast = 0;

  /* DHCP needs special treatment since we don't know IP yet.  */
  {
    struct disknet_udphdr *udph;
    udph = (struct disknet_udphdr *) nb->data;
    if (proto == disknet_grub_net_IP_UDP && grub_be_to_cpu16 (udph->dst) == 68)
      {
	const struct disknet_grub_net_bootp_packet *bootp;
	if (udph->chksum)
	  {
	    grub_uint16_t chk, expected;
	    chk = udph->chksum;
	    udph->chksum = 0;
	    expected = disknet_grub_net_ip_transport_checksum (nb,
						       disknet_grub_net_IP_UDP,
						       source,
						       dest);
	    if (expected != chk)
	      {
		grub_dprintf ("net", "Invalid UDP checksum. "
			      "Expected %x, got %x\n",
			      grub_be_to_cpu16 (expected),
			      grub_be_to_cpu16 (chk));
		disknet_grub_netbuff_free (nb);
		return GRUB_ERR_NONE;
	      }
	    udph->chksum = chk;
	  }

	err = disknet_grub_netbuff_pull (nb, sizeof (*udph));
	if (err)
	  {
	    disknet_grub_netbuff_free (nb);
	    return err;
	  }

	bootp = (const struct disknet_grub_net_bootp_packet *) nb->data;

	FOR_NET_NETWORK_LEVEL_INTERFACES (inf)
	  if (inf->card == card
	      && inf->address.type == disknet_grub_net_NETWORK_LEVEL_PROTOCOL_DHCP_RECV
	      && inf->hwaddress.type == disknet_grub_net_LINK_LEVEL_PROTOCOL_ETHERNET
	      && grub_memcmp (inf->hwaddress.mac, &bootp->mac_addr,
			      sizeof (inf->hwaddress.mac)) == 0)
	    {
	      disknet_grub_net_process_dhcp (nb, inf);
	      disknet_grub_netbuff_free (nb);
	      return GRUB_ERR_NONE;
	    }
	disknet_grub_netbuff_free (nb);
	return GRUB_ERR_NONE;
      }
  }

  FOR_NET_NETWORK_LEVEL_INTERFACES (inf)
  {
    if (inf->card == card
	&& disknet_grub_net_addr_cmp (&inf->address, dest) == 0
	&& disknet_grub_net_hwaddr_cmp (&inf->hwaddress, hwaddress) == 0)
      break;

    /* Verify vlantag id */
    if (inf->card == card && inf->vlantag != *vlantag)
      {
        grub_dprintf ("net", "invalid vlantag! %x != %x\n",
                      inf->vlantag, *vlantag);
        break;
      }

    /* Solicited node multicast.  */
    if (inf->card == card
	&& inf->address.type == disknet_grub_net_NETWORK_LEVEL_PROTOCOL_IPV6
	&& dest->type == disknet_grub_net_NETWORK_LEVEL_PROTOCOL_IPV6
	&& dest->ipv6[0] == grub_be_to_cpu64_compile_time (0xff02ULL << 48)
	&& dest->ipv6[1] == (grub_be_to_cpu64_compile_time (0x01ff000000ULL)
			     | (inf->address.ipv6[1]
				& grub_be_to_cpu64_compile_time (0xffffff)))
	&& hwaddress->type == disknet_grub_net_LINK_LEVEL_PROTOCOL_ETHERNET
	&& hwaddress->mac[0] == 0x33 && hwaddress->mac[1] == 0x33
	&& hwaddress->mac[2] == 0xff
	&& hwaddress->mac[3] == ((grub_be_to_cpu64 (inf->address.ipv6[1])
				  >> 16) & 0xff)
	&& hwaddress->mac[4] == ((grub_be_to_cpu64 (inf->address.ipv6[1])
				  >> 8) & 0xff)
	&& hwaddress->mac[5] == ((grub_be_to_cpu64 (inf->address.ipv6[1])
				  >> 0) & 0xff))
      {
	multicast = 1;
	break;
      }
  }

  if (!inf && !(dest->type == disknet_grub_net_NETWORK_LEVEL_PROTOCOL_IPV6
		&& dest->ipv6[0] == grub_be_to_cpu64_compile_time (0xff02ULL
								   << 48)
		&& dest->ipv6[1] == grub_be_to_cpu64_compile_time (1)))
    {
      disknet_grub_netbuff_free (nb);
      return GRUB_ERR_NONE;
    }
  if (multicast)
    inf = NULL;

  switch (proto)
    {
    case disknet_grub_net_IP_UDP:
      return disknet_grub_net_recv_udp_packet (nb, inf, source);
    case disknet_grub_net_IP_TCP:
      return disknet_grub_net_recv_tcp_packet (nb, inf, source);
    case disknet_grub_net_IP_ICMP:
      return disknet_grub_net_recv_icmp_packet (nb, inf, source_hwaddress, source);
    case disknet_grub_net_IP_ICMPV6:
      return disknet_grub_net_recv_icmp6_packet (nb, card, inf, source_hwaddress,
					 source, dest, ttl);
    default:
      disknet_grub_netbuff_free (nb);
      break;
    }
  return GRUB_ERR_NONE;
}

static void
free_rsm (struct reassemble *rsm)
{
  struct disknet_grub_net_buff **nb;
  while ((nb = grub_priority_queue_top (rsm->pq)))
    {
      disknet_grub_netbuff_free (*nb);
      grub_priority_queue_pop (rsm->pq);
    }
  disknet_grub_netbuff_free (rsm->asm_netbuff);
  grub_priority_queue_destroy (rsm->pq);
  grub_free (rsm);
}

static void
free_old_fragments (void)
{
  struct reassemble *rsm, **prev;
  grub_uint64_t limit_time = grub_get_time_ms ();

  limit_time = (limit_time > 90000) ? limit_time - 90000 : 0;

  for (prev = &reassembles, rsm = *prev; rsm; rsm = *prev)
    if (rsm->last_time < limit_time)
      {
	*prev = rsm->next;
	free_rsm (rsm);
      }
    else
      {
	prev = &rsm->next;
      }
}

static grub_err_t
disknet_grub_net_recv_ip4_packets (struct disknet_grub_net_buff *nb,
			   struct disknet_grub_net_card *card,
			   const disknet_grub_net_link_level_address_t *hwaddress,
			   const disknet_grub_net_link_level_address_t *src_hwaddress,
                           grub_uint16_t *vlantag)
{
  struct disknet_iphdr *iph = (struct disknet_iphdr *) nb->data;
  grub_err_t err;
  struct reassemble *rsm, **prev;
  if ((iph->verhdrlen >> 4) != 4)
    {
      disknet_grub_netbuff_free (nb);
      return GRUB_ERR_NONE;
    }
  if ((iph->verhdrlen & 0xf) < 5)
    {
      grub_dprintf ("net", "IP header too short: %d\n",
		    (iph->verhdrlen & 0xf));
      disknet_grub_netbuff_free (nb);
      return GRUB_ERR_NONE;
    }
  if (nb->tail - nb->data < (grub_ssize_t) ((iph->verhdrlen & 0xf)
					    * sizeof (grub_uint32_t)))
    {
       grub_dprintf ("net", "IP packet too short: %" PRIdGRUB_SSIZE "\n",
		    (grub_ssize_t) (nb->tail - nb->data));
      disknet_grub_netbuff_free (nb);
      return GRUB_ERR_NONE;
    }

  /* Check size.  */
  {
    grub_size_t expected_size = grub_be_to_cpu16 (iph->len);
    grub_size_t actual_size = (nb->tail - nb->data);
    if (actual_size > expected_size)
      {
	err = disknet_grub_netbuff_unput (nb, actual_size - expected_size);
	if (err)
	  {
	    disknet_grub_netbuff_free (nb);
	    return err;
	  }
      }
    if (actual_size < expected_size)
      {
	grub_dprintf ("net", "Cut IP packet actual: %" PRIuGRUB_SIZE
		      ", expected %" PRIuGRUB_SIZE "\n", actual_size,
		      expected_size);
	disknet_grub_netbuff_free (nb);
	return GRUB_ERR_NONE;
      }
  }

  /* Unfragmented packet. Good.  */
  if (((grub_be_to_cpu16 (iph->frags) & MORE_FRAGMENTS) == 0)
      && (grub_be_to_cpu16 (iph->frags) & OFFSET_MASK) == 0)
    {
      disknet_grub_net_network_level_address_t source;
      disknet_grub_net_network_level_address_t dest;
      err = disknet_grub_netbuff_pull (nb, ((iph->verhdrlen & 0xf)
				    * sizeof (grub_uint32_t)));
      if (err)
	{
	  disknet_grub_netbuff_free (nb);
	  return err;
	}
      source.type = disknet_grub_net_NETWORK_LEVEL_PROTOCOL_IPV4;
      source.ipv4 = iph->src;

      dest.type = disknet_grub_net_NETWORK_LEVEL_PROTOCOL_IPV4;
      dest.ipv4 = iph->dest;
      return disknet_handle_dgram (nb, card, src_hwaddress, hwaddress, iph->protocol,
			   &source, &dest, vlantag, iph->ttl);
    }
  for (prev = &reassembles, rsm = *prev; rsm; prev = &rsm->next, rsm = *prev)
    if (rsm->source == iph->src && rsm->dest == iph->dest
	&& rsm->id == iph->ident && rsm->proto == iph->protocol)
      break;
  if (!rsm)
    {
      rsm = grub_malloc (sizeof (*rsm));
      if (!rsm)
	return grub_errno;
      rsm->source = iph->src;
      rsm->dest = iph->dest;
      rsm->id = iph->ident;
      rsm->proto = iph->protocol;
      rsm->next = reassembles;
      reassembles = rsm;
      prev = &reassembles;
      rsm->pq = grub_priority_queue_new (sizeof (struct disknet_grub_net_buff **), cmp);
      if (!rsm->pq)
	{
	  grub_free (rsm);
	  return grub_errno;
	}
      rsm->asm_netbuff = 0;
      rsm->total_len = 0;
      rsm->cur_ptr = 0;
      rsm->ttl = 0xff;
    }
  if (rsm->ttl > iph->ttl)
    rsm->ttl = iph->ttl;
  rsm->last_time = grub_get_time_ms ();
  free_old_fragments ();

  err = grub_priority_queue_push (rsm->pq, &nb);
  if (err)
    return err;

  if (!(grub_be_to_cpu16 (iph->frags) & MORE_FRAGMENTS))
    {
      rsm->total_len = (8 * (grub_be_to_cpu16 (iph->frags) & OFFSET_MASK)
			+ (nb->tail - nb->data));
      rsm->total_len -= ((iph->verhdrlen & 0xf) * sizeof (grub_uint32_t));
      rsm->asm_netbuff = disknet_grub_netbuff_alloc (rsm->total_len);
      if (!rsm->asm_netbuff)
	{
	  *prev = rsm->next;
	  free_rsm (rsm);
	  return grub_errno;
	}
    }
  if (!rsm->asm_netbuff)
    return GRUB_ERR_NONE;

  while (1)
    {
      struct disknet_grub_net_buff **nb_top_p, *nb_top;
      grub_size_t copy;
      grub_size_t res_len;
      struct disknet_grub_net_buff *ret;
      disknet_grub_net_ip_protocol_t proto;
      grub_uint32_t src;
      grub_uint32_t dst;
      disknet_grub_net_network_level_address_t source;
      disknet_grub_net_network_level_address_t dest;
      grub_uint8_t ttl;

      nb_top_p = grub_priority_queue_top (rsm->pq);
      if (!nb_top_p)
	return GRUB_ERR_NONE;
      nb_top = *nb_top_p;
      grub_priority_queue_pop (rsm->pq);
      iph = (struct disknet_iphdr *) nb_top->data;
      err = disknet_grub_netbuff_pull (nb_top, ((iph->verhdrlen & 0xf)
					* sizeof (grub_uint32_t)));
      if (err)
	{
	  disknet_grub_netbuff_free (nb_top);
	  return err;
	}
      if (rsm->cur_ptr < (grub_size_t) 8 * (grub_be_to_cpu16 (iph->frags)
					    & OFFSET_MASK))
	{
	  disknet_grub_netbuff_free (nb_top);
	  return GRUB_ERR_NONE;
	}

      rsm->cur_ptr = (8 * (grub_be_to_cpu16 (iph->frags) & OFFSET_MASK)
		      + (nb_top->tail - nb_top->head));
      if ((grub_size_t) 8 * (grub_be_to_cpu16 (iph->frags) & OFFSET_MASK)
	  >= rsm->total_len)
	{
	  disknet_grub_netbuff_free (nb_top);
	  continue;
	}
      copy = nb_top->tail - nb_top->data;
      if (rsm->total_len - 8 * (grub_be_to_cpu16 (iph->frags) & OFFSET_MASK)
	  < copy)
	copy = rsm->total_len - 8 * (grub_be_to_cpu16 (iph->frags)
				     & OFFSET_MASK);
      grub_memcpy (&rsm->asm_netbuff->data[8 * (grub_be_to_cpu16 (iph->frags)
						& OFFSET_MASK)],
		   nb_top->data, copy);

      if ((grub_be_to_cpu16 (iph->frags) & MORE_FRAGMENTS))
	{
	  disknet_grub_netbuff_free (nb_top);
	  continue;
	}
      disknet_grub_netbuff_free (nb_top);

      ret = rsm->asm_netbuff;
      proto = rsm->proto;
      src = rsm->source;
      dst = rsm->dest;
      ttl = rsm->ttl;

      rsm->asm_netbuff = 0;
      res_len = rsm->total_len;
      *prev = rsm->next;
      free_rsm (rsm);

      if (disknet_grub_netbuff_put (ret, res_len))
	{
	  disknet_grub_netbuff_free (ret);
	  return GRUB_ERR_NONE;
	}

      source.type = disknet_grub_net_NETWORK_LEVEL_PROTOCOL_IPV4;
      source.ipv4 = src;

      dest.type = disknet_grub_net_NETWORK_LEVEL_PROTOCOL_IPV4;
      dest.ipv4 = dst;

      return disknet_handle_dgram (ret, card, src_hwaddress,
			   hwaddress, proto, &source, &dest, vlantag,
			   ttl);
    }
}

static grub_err_t
disknet_grub_net_send_ip6_packet (struct disknet_grub_net_network_level_interface *inf,
			  const disknet_grub_net_network_level_address_t *target,
			  const disknet_grub_net_link_level_address_t *ll_target_addr,
			  struct disknet_grub_net_buff *nb,
			  disknet_grub_net_ip_protocol_t proto)
{
  struct ip6hdr *iph;
  grub_err_t err;

  COMPILE_TIME_ASSERT (disknet_grub_net_OUR_IPV6_HEADER_SIZE == sizeof (*iph));

  if (nb->tail - nb->data + sizeof (struct disknet_iphdr) > inf->card->mtu)
    return grub_error (GRUB_ERR_NET_PACKET_TOO_BIG, "packet too big");

  err = disknet_grub_netbuff_push (nb, sizeof (*iph));
  if (err)
    return err;

  iph = (struct ip6hdr *) nb->data;
  iph->version_class_flow = grub_cpu_to_be32_compile_time ((6 << 28));
  iph->len = grub_cpu_to_be16 (nb->tail - nb->data - sizeof (*iph));
  iph->protocol = proto;
  iph->ttl = 0xff;
  grub_memcpy (&iph->src, inf->address.ipv6, sizeof (iph->src));
  grub_memcpy (&iph->dest, target->ipv6, sizeof (iph->dest));

  return disknet_send_ethernet_packet (inf, nb, *ll_target_addr,
			       disknet_grub_net_ETHERTYPE_IP6);
}

grub_err_t
disknet_grub_net_send_ip_packet (struct disknet_grub_net_network_level_interface *inf,
			 const disknet_grub_net_network_level_address_t *target,
			 const disknet_grub_net_link_level_address_t *ll_target_addr,
			 struct disknet_grub_net_buff *nb,
			 disknet_grub_net_ip_protocol_t proto)
{
  switch (target->type)
    {
    case disknet_grub_net_NETWORK_LEVEL_PROTOCOL_IPV4:
      return disknet_grub_net_send_ip4_packet (inf, target, ll_target_addr, nb, proto);
    case disknet_grub_net_NETWORK_LEVEL_PROTOCOL_IPV6:
      return disknet_grub_net_send_ip6_packet (inf, target, ll_target_addr, nb, proto);
    default:
      return grub_error (GRUB_ERR_BUG, "not an IP");
    }
}

static grub_err_t
disknet_grub_net_recv_ip6_packets (struct disknet_grub_net_buff *nb,
			   struct disknet_grub_net_card *card,
			   const disknet_grub_net_link_level_address_t *hwaddress,
			   const disknet_grub_net_link_level_address_t *src_hwaddress,
                           grub_uint16_t *vlantag)
{
  struct ip6hdr *iph = (struct ip6hdr *) nb->data;
  grub_err_t err;
  disknet_grub_net_network_level_address_t source;
  disknet_grub_net_network_level_address_t dest;

  if (nb->tail - nb->data < (grub_ssize_t) sizeof (*iph))
    {
      grub_dprintf ("net", "IP packet too short: %" PRIdGRUB_SSIZE "\n",
		    (grub_ssize_t) (nb->tail - nb->data));
      disknet_grub_netbuff_free (nb);
      return GRUB_ERR_NONE;
    }

  err = disknet_grub_netbuff_pull (nb, sizeof (*iph));
  if (err)
    {
      disknet_grub_netbuff_free (nb);
      return err;
    }

  /* Check size.  */
  {
    grub_size_t expected_size = grub_be_to_cpu16 (iph->len);
    grub_size_t actual_size = (nb->tail - nb->data);
    if (actual_size > expected_size)
      {
	err = disknet_grub_netbuff_unput (nb, actual_size - expected_size);
	if (err)
	  {
	    disknet_grub_netbuff_free (nb);
	    return err;
	  }
      }
    if (actual_size < expected_size)
      {
	grub_dprintf ("net", "Cut IP packet actual: %" PRIuGRUB_SIZE
		      ", expected %" PRIuGRUB_SIZE "\n", actual_size,
		      expected_size);
	disknet_grub_netbuff_free (nb);
	return GRUB_ERR_NONE;
      }
  }

  source.type = disknet_grub_net_NETWORK_LEVEL_PROTOCOL_IPV6;
  dest.type = disknet_grub_net_NETWORK_LEVEL_PROTOCOL_IPV6;
  grub_memcpy (source.ipv6, &iph->src, sizeof (source.ipv6));
  grub_memcpy (dest.ipv6, &iph->dest, sizeof (dest.ipv6));

  return disknet_handle_dgram (nb, card, src_hwaddress, hwaddress, iph->protocol,
		       &source, &dest, vlantag, iph->ttl);
}

grub_err_t
disknet_grub_net_recv_ip_packets (struct disknet_grub_net_buff *nb,
			  struct disknet_grub_net_card *card,
			  const disknet_grub_net_link_level_address_t *hwaddress,
			  const disknet_grub_net_link_level_address_t *src_hwaddress,
                          grub_uint16_t *vlantag)
{
  struct disknet_iphdr *iph = (struct disknet_iphdr *) nb->data;
  if ((iph->verhdrlen >> 4) == 4)
    return disknet_grub_net_recv_ip4_packets (nb, card, hwaddress, src_hwaddress,
                                      vlantag);
  if ((iph->verhdrlen >> 4) == 6)
    return disknet_grub_net_recv_ip6_packets (nb, card, hwaddress, src_hwaddress,
                                      vlantag);
  grub_dprintf ("net", "Bad IP version: %d\n", (iph->verhdrlen >> 4));
  disknet_grub_netbuff_free (nb);
  return GRUB_ERR_NONE;
}
