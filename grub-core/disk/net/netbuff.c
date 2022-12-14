/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010 Free Software Foundation, Inc.
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

#include "netbuff.h"

grub_err_t
disknet_grub_netbuff_put (struct disknet_grub_net_buff *nb, grub_size_t len)
{
  nb->tail += len;
  if (nb->tail > nb->end)
    return grub_error (GRUB_ERR_BUG, "put out of the packet range.");
  return GRUB_ERR_NONE;
}

grub_err_t
disknet_grub_netbuff_unput (struct disknet_grub_net_buff *nb, grub_size_t len)
{
  nb->tail -= len;
  if (nb->tail < nb->head)
    return grub_error (GRUB_ERR_BUG,
		       "unput out of the packet range.");
  return GRUB_ERR_NONE;
}

grub_err_t
disknet_grub_netbuff_push (struct disknet_grub_net_buff *nb, grub_size_t len)
{
  nb->data -= len;
  if (nb->data < nb->head)
    return grub_error (GRUB_ERR_BUG,
		       "push out of the packet range.");
  return GRUB_ERR_NONE;
}

grub_err_t
disknet_grub_netbuff_pull (struct disknet_grub_net_buff *nb, grub_size_t len)
{
  nb->data += len;
  if (nb->data > nb->end || nb->data > nb->tail)
    return grub_error (GRUB_ERR_BUG,
		       "pull out of the packet range.");
  return GRUB_ERR_NONE;
}

grub_err_t
disknet_grub_netbuff_reserve (struct disknet_grub_net_buff *nb, grub_size_t len)
{
  nb->data += len;
  nb->tail += len;
  if ((nb->tail > nb->end) || (nb->data > nb->end))
    return grub_error (GRUB_ERR_BUG,
		       "reserve out of the packet range.");
  return GRUB_ERR_NONE;
}

struct disknet_grub_net_buff *
disknet_grub_netbuff_alloc (grub_size_t len)
{
  struct disknet_grub_net_buff *nb;
  void *data;

  COMPILE_TIME_ASSERT (NETBUFF_ALIGN % sizeof (grub_properly_aligned_t) == 0);

  if (len < NETBUFFMINLEN)
    len = NETBUFFMINLEN;

  len = ALIGN_UP (len, NETBUFF_ALIGN);
  data = grub_malloc (len + sizeof (*nb));

#ifdef GRUB_MACHINE_EMU
#else
 // data = grub_memalign (NETBUFF_ALIGN, len + sizeof (*nb));
#endif
  if (!data)
    return NULL;
  nb = (struct disknet_grub_net_buff *) ((grub_properly_aligned_t *) data
				 + len / sizeof (grub_properly_aligned_t));
  nb->head = nb->data = nb->tail = data;
  nb->end = (grub_uint8_t *) nb;
  return nb;
}

struct disknet_grub_net_buff *
disknet_grub_netbuff_make_pkt (grub_size_t len)
{
  struct disknet_grub_net_buff *nb;
  grub_err_t err;
  nb = disknet_grub_netbuff_alloc (len + 512);
  if (!nb)
    return NULL;
  err = disknet_grub_netbuff_reserve (nb, len + 512);
  if (err)
    goto fail;
  err = disknet_grub_netbuff_push (nb, len);
  if (err)
    goto fail;
  return nb;
 fail:
  disknet_grub_netbuff_free (nb);
  return NULL;
}

void
disknet_grub_netbuff_free (struct disknet_grub_net_buff *nb)
{
  if (!nb)
    return;
  grub_free (nb->head);
}

grub_err_t
disknet_grub_netbuff_clear (struct disknet_grub_net_buff *nb)
{
  nb->data = nb->tail = nb->head;
  return GRUB_ERR_NONE;
}
