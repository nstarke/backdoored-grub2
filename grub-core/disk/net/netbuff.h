#ifndef GRUB_NETBUFF_HEADER
#define GRUB_NETBUFF_HEADER

#include <grub/misc.h>
#include <grub/err.h>
#include <grub/misc.h>
#include <grub/mm.h>

#define NETBUFF_ALIGN 2048
#define NETBUFFMINLEN 64

struct disknet_grub_net_buff
{
  /* Pointer to the start of the buffer.  */
  grub_uint8_t *head;
  /* Pointer to the data.  */
  grub_uint8_t *data;
  /* Pointer to the tail.  */
  grub_uint8_t *tail;
  /* Pointer to the end of the buffer.  */
  grub_uint8_t *end;
};

grub_err_t disknet_grub_netbuff_put (struct disknet_grub_net_buff *net_buff, grub_size_t len);
grub_err_t disknet_grub_netbuff_unput (struct disknet_grub_net_buff *net_buff, grub_size_t len);
grub_err_t disknet_grub_netbuff_push (struct disknet_grub_net_buff *net_buff, grub_size_t len);
grub_err_t disknet_grub_netbuff_pull (struct disknet_grub_net_buff *net_buff, grub_size_t len);
grub_err_t disknet_grub_netbuff_reserve (struct disknet_grub_net_buff *net_buff, grub_size_t len);
grub_err_t disknet_grub_netbuff_clear (struct disknet_grub_net_buff *net_buff);
struct disknet_grub_net_buff * disknet_grub_netbuff_alloc (grub_size_t len);
struct disknet_grub_net_buff * disknet_grub_netbuff_make_pkt (grub_size_t len);
void disknet_grub_netbuff_free (struct disknet_grub_net_buff *net_buff);

#endif
