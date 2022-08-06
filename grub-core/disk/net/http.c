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
#include <grub/dl.h>
#include <grub/file.h>
#include <grub/i18n.h>
#include "http.h"
#include "tcp.h"
#include "ip.h"
#include "ethernet.h"
#include "netbuff.h"
#include "net.h"

GRUB_MOD_LICENSE ("GPLv3+");

enum
  {
    HTTP_PORT = 80
  };


typedef struct http_data
{
  char *current_line;
  grub_size_t current_line_len;
  int headers_recv;
  int first_line_recv;
  int size_recv;
  disknet_grub_net_tcp_socket_t sock;
  char *filename;
  grub_err_t err;
  char *errmsg;
  int chunked;
  grub_size_t chunk_rem;
  int in_chunk_len;
} *http_data_t;

static grub_off_t
have_ahead (struct grub_file *file)
{
  disknet_grub_net_t net = file->device->disknet;
  grub_off_t ret = net->offset;
  struct disknet_grub_net_packet *pack;
  for (pack = net->packs.first; pack; pack = pack->next)
    ret += pack->nb->tail - pack->nb->data;
  return ret;
}

static grub_err_t
parse_line (grub_file_t file, http_data_t data, char *ptr, grub_size_t len)
{
  char *end = ptr + len;
  while (end > ptr && *(end - 1) == '\r')
    end--;
  *end = 0;
  /* Trailing CRLF.  */
  if (data->in_chunk_len == 1)
    {
      data->in_chunk_len = 2;
      return GRUB_ERR_NONE;
    }
  if (data->in_chunk_len == 2)
    {
      data->chunk_rem = grub_strtoul (ptr, 0, 16);
      grub_errno = GRUB_ERR_NONE;
      if (data->chunk_rem == 0)
	{file->device->disknet->eof = 1;
	  file->device->disknet->stall = 1;
	  
	  if (file->size == GRUB_FILE_SIZE_UNKNOWN)
	    file->size = have_ahead (file);
	}
      data->in_chunk_len = 0;
      return GRUB_ERR_NONE;
    }
  if (ptr == end)
    {
      data->headers_recv = 1;
      if (data->chunked)
	data->in_chunk_len = 2;
      return GRUB_ERR_NONE;
    }

  if (!data->first_line_recv)
    {
      int code;
      if (grub_memcmp (ptr, "HTTP/1.1 ", sizeof ("HTTP/1.1 ") - 1) != 0)
	{
	  data->errmsg = grub_strdup (_("unsupported HTTP response"));
	  data->first_line_recv = 1;
	  return GRUB_ERR_NONE;
	}
      ptr += sizeof ("HTTP/1.1 ") - 1;
      code = grub_strtoul (ptr, (const char **)&ptr, 10);
      if (grub_errno)
	return grub_errno;
      switch (code)
	{
	case 200:
	case 206:
	  break;
	case 404:
	  data->err = GRUB_ERR_FILE_NOT_FOUND;
	  data->errmsg = grub_xasprintf (_("file `%s' not found"), data->filename);
	  return GRUB_ERR_NONE;
	default:
	  data->err = GRUB_ERR_NET_UNKNOWN_ERROR;
	  /* TRANSLATORS: GRUB HTTP code is pretty young. So even perfectly
	     valid answers like 403 will trigger this very generic message.  */
	  data->errmsg = grub_xasprintf (_("unsupported HTTP error %d: %s"),
					 code, ptr);
	  return GRUB_ERR_NONE;
	}
      data->first_line_recv = 1;
      return GRUB_ERR_NONE;
    }
  if (grub_memcmp (ptr, "Content-Length: ", sizeof ("Content-Length: ") - 1)
      == 0 && !data->size_recv)
    {
      ptr += sizeof ("Content-Length: ") - 1;
      file->size = grub_strtoull (ptr, (const char **)&ptr, 10);
      data->size_recv = 1;
      return GRUB_ERR_NONE;
    }
  if (grub_memcmp (ptr, "Transfer-Encoding: chunked",
		   sizeof ("Transfer-Encoding: chunked") - 1) == 0)
    {
      data->chunked = 1;
      return GRUB_ERR_NONE;
    }

  return GRUB_ERR_NONE;
}

static void
http_err (disknet_grub_net_tcp_socket_t sock __attribute__ ((unused)),
	  void *f)
{
  grub_file_t file = f;
  http_data_t data = file->data;

  if (data->sock)
    disknet_grub_net_tcp_close (data->sock, disknet_grub_net_TCP_ABORT);
  data->sock = 0;
  if (data->current_line)
    grub_free (data->current_line);
  data->current_line = 0;
  file->device->disknet->eof = 1;
  file->device->disknet->stall = 1;
  if (file->size == GRUB_FILE_SIZE_UNKNOWN)
    file->size = have_ahead (file);
}

static grub_err_t
http_receive (disknet_grub_net_tcp_socket_t sock __attribute__ ((unused)),
	      struct disknet_grub_net_buff *nb,
	      void *f)
{
  grub_file_t file = f;
  http_data_t data = file->data;
  grub_err_t err;

  if (!data->sock)
    {
      disknet_grub_netbuff_free (nb);
      return GRUB_ERR_NONE;
    }

  while (1)
    {
      char *ptr = (char *) nb->data;
      if ((!data->headers_recv || data->in_chunk_len) && data->current_line)
	{
	  int have_line = 1;
	  char *t;
	  ptr = grub_memchr (nb->data, '\n', nb->tail - nb->data);
	  if (ptr)
	    ptr++;
	  else
	    {
	      have_line = 0;
	      ptr = (char *) nb->tail;
	    }
	  t = grub_realloc (data->current_line,
			    data->current_line_len + (ptr - (char *) nb->data));
	  if (!t)
	    {
	      disknet_grub_netbuff_free (nb);
	      disknet_grub_net_tcp_close (data->sock, disknet_grub_net_TCP_ABORT);
	      return grub_errno;
	    }

	  data->current_line = t;
	  grub_memcpy (data->current_line + data->current_line_len,
		       nb->data, ptr - (char *) nb->data);
	  data->current_line_len += ptr - (char *) nb->data;
	  if (!have_line)
	    {
	      disknet_grub_netbuff_free (nb);
	      return GRUB_ERR_NONE;
	    }
	  err = parse_line (file, data, data->current_line,
			    data->current_line_len);
	  grub_free (data->current_line);
	  data->current_line = 0;
	  data->current_line_len = 0;
	  if (err)
	    {
	      disknet_grub_net_tcp_close (data->sock, disknet_grub_net_TCP_ABORT);
	      disknet_grub_netbuff_free (nb);
	      return err;
	    }
	}

      while (ptr < (char *) nb->tail && (!data->headers_recv
					 || data->in_chunk_len))
	{
	  char *ptr2;
	  ptr2 = grub_memchr (ptr, '\n', (char *) nb->tail - ptr);
	  if (!ptr2)
	    {
	      data->current_line = grub_malloc ((char *) nb->tail - ptr);
	      if (!data->current_line)
		{
		  disknet_grub_netbuff_free (nb);
		  disknet_grub_net_tcp_close (data->sock, disknet_grub_net_TCP_ABORT);
		  return grub_errno;
		}
	      data->current_line_len = (char *) nb->tail - ptr;
	      grub_memcpy (data->current_line, ptr, data->current_line_len);
	      disknet_grub_netbuff_free (nb);
	      return GRUB_ERR_NONE;
	    }
	  err = parse_line (file, data, ptr, ptr2 - ptr);
	  if (err)
	    {
	      disknet_grub_net_tcp_close (data->sock, disknet_grub_net_TCP_ABORT);
	      disknet_grub_netbuff_free (nb);
	      return err;
	    }
	  ptr = ptr2 + 1;
	}

      if (((char *) nb->tail - ptr) <= 0)
	{
	  disknet_grub_netbuff_free (nb);
	  return GRUB_ERR_NONE;
	}
      err = disknet_grub_netbuff_pull (nb, ptr - (char *) nb->data);
      if (err)
	{
	  disknet_grub_net_tcp_close (data->sock, disknet_grub_net_TCP_ABORT);
	  disknet_grub_netbuff_free (nb);
	  return err;
	}
      if (!(data->chunked && (grub_ssize_t) data->chunk_rem
	    < nb->tail - nb->data))
	{
	  disknet_grub_net_put_packet (&file->device->disknet->packs, nb);
	  if (file->device->disknet->packs.count >= 20)
	    file->device->disknet->stall = 1;

	  if (file->device->disknet->packs.count >= 100)
	    disknet_grub_net_tcp_stall (data->sock);

	  if (data->chunked)
	    data->chunk_rem -= nb->tail - nb->data;
	  return GRUB_ERR_NONE;
	}
      if (data->chunk_rem)
	{
	  struct disknet_grub_net_buff *nb2;
	  nb2 = disknet_grub_netbuff_alloc (data->chunk_rem);
	  if (!nb2)
	    return grub_errno;
	  disknet_grub_netbuff_put (nb2, data->chunk_rem);
	  grub_memcpy (nb2->data, nb->data, data->chunk_rem);
	  if (file->device->disknet->packs.count >= 20)
	    {
	      file->device->disknet->stall = 1;
	      disknet_grub_net_tcp_stall (data->sock);
	    }

	  disknet_grub_net_put_packet (&file->device->disknet->packs, nb2);
	  disknet_grub_netbuff_pull (nb, data->chunk_rem);
	}
      data->in_chunk_len = 1;
    }
}

grub_err_t
disknet_http_establish (const char *filename, grub_off_t offset, int initial, const char* host)
{
  grub_file_t file;
  grub_uint8_t *ptr;
  int i;
  struct disknet_grub_net_buff *nb;
  grub_err_t err;
  char *server_name;
  char *port_string;
  const char *port_string_end;
  unsigned long port_number;
  int headers_recv = 0;
  file = grub_malloc(sizeof(grub_file_t));
  nb = disknet_grub_netbuff_alloc (disknet_grub_net_TCP_RESERVE_SIZE
			   + sizeof ("GET ") - 1
			   + grub_strlen (filename)
			   + sizeof (" HTTP/1.1\r\nHost: ") - 1
			   + grub_strlen (host)
			   + sizeof ("\r\nUser-Agent: " PACKAGE_STRING
				     "\r\n") - 1
			   + sizeof ("Range: bytes=XXXXXXXXXXXXXXXXXXXX"
				     "-\r\n\r\n"));
  if (!nb)
    return grub_errno;

  disknet_grub_netbuff_reserve (nb, disknet_grub_net_TCP_RESERVE_SIZE);
  ptr = nb->tail;
  err = disknet_grub_netbuff_put (nb, sizeof ("GET ") - 1);
  if (err)
    {
      disknet_grub_netbuff_free (nb);
      return err;
    }
  grub_memcpy (ptr, "GET ", sizeof ("GET ") - 1);

  ptr = nb->tail;

  err = disknet_grub_netbuff_put (nb, grub_strlen (filename));
  if (err)
    {
      disknet_grub_netbuff_free (nb);
      return err;
    }
  grub_memcpy (ptr, filename, grub_strlen (filename));

  ptr = nb->tail;
  err = disknet_grub_netbuff_put (nb, sizeof (" HTTP/1.1\r\nHost: ") - 1);
  if (err)
    {
      disknet_grub_netbuff_free (nb);
      return err;
    }
  grub_memcpy (ptr, " HTTP/1.1\r\nHost: ",
	       sizeof (" HTTP/1.1\r\nHost: ") - 1);

  ptr = nb->tail;
  err = disknet_grub_netbuff_put (nb, grub_strlen (host));
  if (err)
    {
      disknet_grub_netbuff_free (nb);
      return err;
    }
  grub_memcpy (ptr, host,
	       grub_strlen (host));

  ptr = nb->tail;
  err = disknet_grub_netbuff_put (nb,
			  sizeof ("\r\nUser-Agent: " PACKAGE_STRING "\r\n")
			  - 1);
  if (err)
    {
      disknet_grub_netbuff_free (nb);
      return err;
    }
  grub_memcpy (ptr, "\r\nUser-Agent: " PACKAGE_STRING "\r\n",
	       sizeof ("\r\nUser-Agent: " PACKAGE_STRING "\r\n") - 1);
  if (!initial)
    {
      ptr = nb->tail;
      grub_snprintf ((char *) ptr,
		     sizeof ("Range: bytes=XXXXXXXXXXXXXXXXXXXX-"
			     "\r\n"),
		     "Range: bytes=%" PRIuGRUB_UINT64_T "-\r\n",
		     offset);
      disknet_grub_netbuff_put (nb, grub_strlen ((char *) ptr));
    }
  ptr = nb->tail;
  disknet_grub_netbuff_put (nb, 2);
  grub_memcpy (ptr, "\r\n", 2);

  port_string = grub_strrchr (host, ',');
  if (port_string == NULL)
    {
      /* If ",port" is not found in the http server string, look for ":port". */
      port_string = grub_strrchr (host, ':');
      /* For IPv6 addresses, the ":port" syntax is not supported and ",port" must be used. */
      if (port_string != NULL && grub_strchr (host, ':') != port_string)
	  port_string = NULL;
    }
  if (port_string != NULL)
    {
      port_number = grub_strtoul (port_string + 1, &port_string_end, 10);
      if (*(port_string + 1) == '\0' || *port_string_end != '\0')
	  return grub_error (GRUB_ERR_BAD_NUMBER, N_("non-numeric or invalid port number `%s'"), port_string + 1);
      if (port_number == 0 || port_number > 65535)
	  return grub_error (GRUB_ERR_OUT_OF_RANGE, N_("port number `%s' not in the range of 1 to 65535"), port_string + 1);

      server_name = grub_strdup (host);
      if (server_name == NULL)
	  return grub_errno;
      server_name[port_string - host] = '\0';
    }
  else
    {
      port_number = HTTP_PORT;
      server_name = (char *)host;
    }
  disknet_grub_net_tcp_socket_t sock = disknet_grub_net_tcp_open (server_name,
				  port_number, http_receive,
				  http_err, NULL,
				  file);
  if (!sock)
    {
      disknet_grub_netbuff_free (nb);
      return grub_errno;
    }

  disknet_grub_net_poll_cards (5000, 0);
  err = disknet_grub_net_send_tcp_packet (sock, nb, 1);
  if (err)
    {
      disknet_grub_net_tcp_close (sock, disknet_grub_net_TCP_ABORT);
      return err;
    }

  for (i = 0; !headers_recv && i < 100; i++)
    {
      disknet_grub_net_tcp_retransmit ();
      disknet_grub_net_poll_cards (300, &headers_recv);
    }

  if (!headers_recv)
    {
      disknet_grub_net_tcp_close (sock, disknet_grub_net_TCP_ABORT);
      if (err)
	{
	  const char *str ="someone set us up the bomb\n";
	  err = grub_error (err, "%s", str);
	  return err;
	}
      return grub_error (GRUB_ERR_TIMEOUT, N_("time out opening `%s'"), filename);
    }
  return GRUB_ERR_NONE;
}

// static grub_err_t
// http_seek (struct grub_file *file, grub_off_t off)
// {
//   struct http_data *old_data, *data;
//   grub_err_t err;
//   old_data = file->data;
//   /* FIXME: Reuse socket?  */
//   if (old_data->sock)
//     disknet_grub_net_tcp_close (old_data->sock, disknet_grub_net_TCP_ABORT);
//   old_data->sock = 0;

//   while (file->device->disknet->packs.first)
//     {
//       disknet_grub_netbuff_free (file->device->disknet->packs.first->nb);
//       disknet_grub_net_remove_packet (file->device->disknet->packs.first);
//     }

//   file->device->disknet->stall = 0;
//   file->device->disknet->eof = 0;
//   file->device->disknet->offset = off;

//   data = grub_zalloc (sizeof (*data));
//   if (!data)
//     return grub_errno;

//   data->size_recv = 1;
//   data->filename = old_data->filename;
//   if (!data->filename)
//     {
//       grub_free (data);
//       file->data = 0;
//       return grub_errno;
//     }
//   grub_free (old_data);

//   file->data = data;
//  // err = disknet_http_establish (file, off, 0);
//   if (err)
//     {
//       grub_free (data->filename);
//       grub_free (data);
//       file->data = 0;
//       return err;
//     }
//   return GRUB_ERR_NONE;
// }

// // static grub_err_t
// // http_open (const char *host, const char *filename)
// // {
// //   return disknet_http_establish (filename, 0, 1, host);
// // }

// static grub_err_t
// http_close (struct grub_file *file)
// {
//   http_data_t data = file->data;

//   if (!data)
//     return GRUB_ERR_NONE;

//   if (data->sock)
//     disknet_grub_net_tcp_close (data->sock, disknet_grub_net_TCP_ABORT);
//   if (data->current_line)
//     grub_free (data->current_line);
//   grub_free (data->filename);
//   grub_free (data);
//   return GRUB_ERR_NONE;
// }

// static grub_err_t
// http_packets_pulled (struct grub_file *file)
// {
//   http_data_t data = file->data;

//   if (file->device->disknet->packs.count >= 20)
//     return 0;

//   if (!file->device->disknet->eof)
//     file->device->disknet->stall = 0;
//   if (data && data->sock)
//     disknet_grub_net_tcp_unstall (data->sock);
//   return 0;
// }
