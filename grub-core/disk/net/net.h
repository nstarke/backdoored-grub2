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

#ifndef disknet_grub_net_HEADER
#define disknet_grub_net_HEADER	1

#include <grub/types.h>
#include <grub/err.h>
#include <grub/list.h>
#include <grub/fs.h>
#include <grub/file.h>
#include <grub/mm.h>
#include "netbuff.h"

enum
  {
    disknet_grub_net_MAX_LINK_HEADER_SIZE = 64,
    disknet_grub_net_UDP_HEADER_SIZE = 8,
    disknet_grub_net_TCP_HEADER_SIZE = 20,
    disknet_grub_net_OUR_IPV4_HEADER_SIZE = 20,
    disknet_grub_net_OUR_IPV6_HEADER_SIZE = 40,
    disknet_grub_net_OUR_MAX_IP_HEADER_SIZE = 40,
    disknet_grub_net_TCP_RESERVE_SIZE = disknet_grub_net_TCP_HEADER_SIZE
    + disknet_grub_net_OUR_IPV4_HEADER_SIZE
    + disknet_grub_net_MAX_LINK_HEADER_SIZE
  };

typedef enum disknet_grub_link_level_protocol_id
{
  disknet_grub_net_LINK_LEVEL_PROTOCOL_ETHERNET
} disknet_grub_link_level_protocol_id_t;

typedef struct disknet_grub_net_link_level_address
{
  disknet_grub_link_level_protocol_id_t type;
  union
  {
    grub_uint8_t mac[6];
  };
} disknet_grub_net_link_level_address_t;

typedef enum disknet_grub_net_interface_flags
  {
    disknet_grub_net_INTERFACE_HWADDRESS_IMMUTABLE = 1,
    disknet_grub_net_INTERFACE_ADDRESS_IMMUTABLE = 2,
    disknet_grub_net_INTERFACE_PERMANENT = 4
  } disknet_grub_net_interface_flags_t;

typedef enum disknet_grub_net_card_flags
  {
    disknet_grub_net_CARD_HWADDRESS_IMMUTABLE = 1,
    disknet_grub_net_CARD_NO_MANUAL_INTERFACES = 2
  } disknet_grub_net_card_flags_t;

struct disknet_grub_net_card;

struct disknet_grub_net_card_driver
{
  struct disknet_grub_net_card_driver *next;
  struct disknet_grub_net_card_driver **prev;
  const char *name;
  grub_err_t (*open) (struct disknet_grub_net_card *dev);
  void (*close) (struct disknet_grub_net_card *dev);
  grub_err_t (*send) (struct disknet_grub_net_card *dev,
		      struct disknet_grub_net_buff *buf);
  struct disknet_grub_net_buff * (*recv) (struct disknet_grub_net_card *dev);
};

typedef struct disknet_grub_net_packet
{
  struct disknet_grub_net_packet *next;
  struct disknet_grub_net_packet *prev;
  struct disknet_grub_net_packets *up;
  struct disknet_grub_net_buff *nb;
} disknet_grub_net_packet_t;

typedef struct disknet_grub_net_packets
{
  disknet_grub_net_packet_t *first;
  disknet_grub_net_packet_t *last;
  grub_size_t count;
} disknet_grub_net_packets_t;

#ifdef GRUB_MACHINE_EFI
#include <grub/efi/api.h>
#endif

struct disknet_grub_net_slaac_mac_list
{
  struct disknet_grub_net_slaac_mac_list *next;
  struct disknet_grub_net_slaac_mac_list **prev;
  disknet_grub_net_link_level_address_t address;
  int slaac_counter;
  char *name;
};

struct disknet_grub_net_link_layer_entry;

struct disknet_grub_net_card
{
  struct disknet_grub_net_card *next;
  struct disknet_grub_net_card **prev;
  const char *name;
  struct disknet_grub_net_card_driver *driver;
  disknet_grub_net_link_level_address_t default_address;
  disknet_grub_net_card_flags_t flags;
  int num_ifaces;
  int opened;
  unsigned idle_poll_delay_ms;
  grub_uint64_t last_poll;
  grub_size_t mtu;
  struct disknet_grub_net_slaac_mac_list *slaac_list;
  grub_ssize_t new_ll_entry;
  struct disknet_grub_net_link_layer_entry *link_layer_table;
  void *txbuf;
  void *rcvbuf;
  grub_size_t rcvbufsize;
  grub_size_t txbufsize;
  int txbusy;
  union
  {
#ifdef GRUB_MACHINE_EFI
    struct
    {
      struct grub_efi_simple_network *efi_net;
      grub_efi_handle_t efi_handle;
      grub_size_t last_pkt_size;
    };
#endif
    void *data;
    int data_num;
  };
};

struct disknet_grub_net_network_level_interface;

typedef enum disknet_grub_lnetwork_level_protocol_id
{
  disknet_grub_net_NETWORK_LEVEL_PROTOCOL_DHCP_RECV,
  disknet_grub_net_NETWORK_LEVEL_PROTOCOL_IPV4,
  disknet_grub_net_NETWORK_LEVEL_PROTOCOL_IPV6
} disknet_grub_lnetwork_level_protocol_id_t;

typedef enum
{
  DISKNET_DNS_OPTION_IPV4,
  DISKNET_DNS_OPTION_IPV6,
  DISKNET_DNS_OPTION_PREFER_IPV4,
  DISKNET_DNS_OPTION_PREFER_IPV6
} disknet_grub_dns_option_t;

typedef struct disknet_grub_net_network_level_address
{
  disknet_grub_lnetwork_level_protocol_id_t type;
  union
  {
    grub_uint32_t ipv4;
    grub_uint64_t ipv6[2];
  };
  disknet_grub_dns_option_t option;
} disknet_grub_net_network_level_address_t;

typedef struct disknet_grub_net_network_level_netaddress
{
  disknet_grub_lnetwork_level_protocol_id_t type;
  union
  {
    struct {
      grub_uint32_t base;
      int masksize;
    } ipv4;
    struct {
      grub_uint64_t base[2];
      int masksize;
    } ipv6;
  };
} disknet_grub_net_network_level_netaddress_t;

struct disknet_grub_net_route
{
  struct disknet_grub_net_route *next;
  struct disknet_grub_net_route **prev;
  disknet_grub_net_network_level_netaddress_t target;
  char *name;
  struct disknet_grub_net_network_level_protocol *prot;
  int is_gateway;
  struct disknet_grub_net_network_level_interface *interface;
  disknet_grub_net_network_level_address_t gw;
};

#define FOR_PACKETS(cont,var) for (var = (cont).first; var; var = var->next)

static inline grub_err_t
disknet_grub_net_put_packet (disknet_grub_net_packets_t *pkts, struct disknet_grub_net_buff *nb)
{
  struct disknet_grub_net_packet *n;

  n = grub_malloc (sizeof (*n));
  if (!n)
    return grub_errno;

  n->nb = nb;
  n->next = NULL;
  n->prev = NULL;
  n->up = pkts;
  if (pkts->first)
    {
      pkts->last->next = n;
      pkts->last = n;
      n->prev = pkts->last;
    }
  else
    pkts->first = pkts->last = n;

  pkts->count++;

  return GRUB_ERR_NONE;
}

static inline void
disknet_grub_net_remove_packet (disknet_grub_net_packet_t *pkt)
{
  pkt->up->count--;

  if (pkt->prev)
    pkt->prev->next = pkt->next;
  else
    pkt->up->first = pkt->next;
  if (pkt->next)
    pkt->next->prev = pkt->prev;
  else
    pkt->up->last = pkt->prev;
  grub_free (pkt);
}

typedef struct disknet_grub_net_app_protocol *disknet_grub_net_app_level_t;

typedef struct disknet_grub_net_socket *disknet_grub_net_socket_t;

struct disknet_grub_net_app_protocol
{
  struct disknet_grub_net_app_protocol *next;
  struct disknet_grub_net_app_protocol **prev;
  const char *name;
  grub_err_t (*dir) (grub_device_t device, const char *path,
		     int (*hook) (const char *filename,
				  const struct grub_dirhook_info *info));
  grub_err_t (*open) (struct grub_file *file, const char *filename);
  grub_err_t (*seek) (struct grub_file *file, grub_off_t off);
  grub_err_t (*close) (struct grub_file *file);
  grub_err_t (*packets_pulled) (struct grub_file *file);
};

typedef struct disknet_grub_net
{
  char *server;
  char *name;
  disknet_grub_net_app_level_t protocol;
  disknet_grub_net_packets_t packs;
  grub_off_t offset;
  grub_fs_t fs;
  int eof;
  int stall;
} *disknet_grub_net_t;

extern disknet_grub_net_t (*EXPORT_VAR (disknet_grub_net_open)) (const char *name);

struct disknet_grub_net_network_level_interface
{
  struct disknet_grub_net_network_level_interface *next;
  struct disknet_grub_net_network_level_interface **prev;
  char *name;
  struct disknet_grub_net_card *card;
  disknet_grub_net_network_level_address_t address;
  disknet_grub_net_link_level_address_t hwaddress;
  disknet_grub_net_interface_flags_t flags;
  struct disknet_grub_net_bootp_packet *dhcp_ack;
  grub_size_t dhcp_acklen;
  grub_uint16_t vlantag;
  grub_uint32_t xid;      /* DHCPv4 transaction id */
  grub_uint32_t srv_id;   /* DHCPv4 server_identifier */
  grub_uint32_t my_ip;    /* DHCPv4 offered IP address */
  unsigned dhcp_tmo_left; /* DHCPv4 running retransmission timeout */
  unsigned dhcp_tmo;      /* DHCPv4 current retransmission timeout */
  void *data;
};

struct disknet_grub_net_session;

struct disknet_grub_net_session_level_protocol
{
  void (*close) (struct disknet_grub_net_session *session);
  grub_ssize_t (*recv) (struct disknet_grub_net_session *session, void *buf,
		       grub_size_t size);
  grub_err_t (*send) (struct disknet_grub_net_session *session, void *buf,
		      grub_size_t size);
};

struct disknet_grub_net_session
{
  struct disknet_grub_net_session_level_protocol *protocol;
  void *data;
};

static inline void
disknet_grub_net_session_close (struct disknet_grub_net_session *session)
{
  session->protocol->close (session);
}

static inline grub_err_t
disknet_grub_net_session_send (struct disknet_grub_net_session *session, void *buf,
		       grub_size_t size)
{
  return session->protocol->send (session, buf, size);
}

static inline grub_ssize_t
disknet_grub_net_session_recv (struct disknet_grub_net_session *session, void *buf,
		       grub_size_t size)
{
  return session->protocol->recv (session, buf, size);
}

struct disknet_grub_net_network_level_interface *
disknet_grub_net_add_addr (const char *name,
		   struct disknet_grub_net_card *card,
		   const disknet_grub_net_network_level_address_t *addr,
		   const disknet_grub_net_link_level_address_t *hwaddress,
		   disknet_grub_net_interface_flags_t flags);

extern struct disknet_grub_net_network_level_interface *disknet_grub_net_network_level_interfaces;
#define FOR_NET_NETWORK_LEVEL_INTERFACES(var) for (var = disknet_grub_net_network_level_interfaces; var; var = var->next)
#define FOR_NET_NETWORK_LEVEL_INTERFACES_SAFE(var,next) for (var = disknet_grub_net_network_level_interfaces, next = (var ? var->next : 0); var; var = next, next = (var ? var->next : 0))


extern disknet_grub_net_app_level_t disknet_grub_net_app_level_list;

#ifndef GRUB_LST_GENERATOR
static inline void
disknet_grub_net_app_level_register (disknet_grub_net_app_level_t proto)
{
  grub_list_push (GRUB_AS_LIST_P (&disknet_grub_net_app_level_list),
		  GRUB_AS_LIST (proto));
}
#endif

static inline void
disknet_grub_net_app_level_unregister (disknet_grub_net_app_level_t proto)
{
  grub_list_remove (GRUB_AS_LIST (proto));
}

#define FOR_NET_APP_LEVEL(var) FOR_LIST_ELEMENTS((var), \
						 (disknet_grub_net_app_level_list))

extern struct disknet_grub_net_card *disknet_grub_net_cards;

static inline void
disknet_grub_net_card_register (struct disknet_grub_net_card *card)
{
  grub_list_push (GRUB_AS_LIST_P (&disknet_grub_net_cards),
		  GRUB_AS_LIST (card));
}

void
disknet_grub_net_card_unregister (struct disknet_grub_net_card *card);

#define FOR_NET_CARDS(var) for (var = disknet_grub_net_cards; var; var = var->next)
#define FOR_NET_CARDS_SAFE(var, next) for (var = disknet_grub_net_cards, next = (var ? var->next : 0); var; var = next, next = (var ? var->next : 0))


extern struct disknet_grub_net_route *disknet_grub_net_routes;

static inline void
disknet_grub_net_route_register (struct disknet_grub_net_route *route)
{
  grub_list_push (GRUB_AS_LIST_P (&disknet_grub_net_routes),
		  GRUB_AS_LIST (route));
}

#define FOR_NET_ROUTES(var) for (var = disknet_grub_net_routes; var; var = var->next)
struct disknet_grub_net_session *
disknet_grub_net_open_tcp (char *address, grub_uint16_t port);

grub_err_t
disknet_grub_net_resolve_address (const char *name,
			  disknet_grub_net_network_level_address_t *addr);

grub_err_t
disknet_grub_net_resolve_net_address (const char *name,
			      disknet_grub_net_network_level_netaddress_t *addr);

grub_err_t
disknet_grub_net_route_address (disknet_grub_net_network_level_address_t addr,
			disknet_grub_net_network_level_address_t *gateway,
			struct disknet_grub_net_network_level_interface **interf);


grub_err_t
disknet_grub_net_add_route (const char *name,
		    disknet_grub_net_network_level_netaddress_t target,
		    struct disknet_grub_net_network_level_interface *inter);

grub_err_t
disknet_grub_net_add_route_gw (const char *name,
		       disknet_grub_net_network_level_netaddress_t target,
		       disknet_grub_net_network_level_address_t gw,
		       struct disknet_grub_net_network_level_interface *inter);


#define disknet_grub_net_BOOTP_MAC_ADDR_LEN	16

typedef grub_uint8_t disknet_grub_net_bootp_mac_addr_t[disknet_grub_net_BOOTP_MAC_ADDR_LEN];

struct disknet_grub_net_bootp_packet
{
  grub_uint8_t opcode;
  grub_uint8_t hw_type;		/* hardware type.  */
  grub_uint8_t hw_len;		/* hardware addr len.  */
  grub_uint8_t gate_hops;	/* zero it.  */
  grub_uint32_t ident;		/* random number chosen by client.  */
  grub_uint16_t seconds;	/* seconds since did initial bootstrap.  */
  grub_uint16_t flags;
  grub_uint32_t	client_ip;
  grub_uint32_t your_ip;
  grub_uint32_t	server_ip;
  grub_uint32_t	gateway_ip;
  disknet_grub_net_bootp_mac_addr_t mac_addr;
  char server_name[64];
  char boot_file[128];
  grub_uint8_t vendor[0];
} GRUB_PACKED;

#define	disknet_grub_net_BOOTP_RFC1048_MAGIC_0	0x63
#define	disknet_grub_net_BOOTP_RFC1048_MAGIC_1	0x82
#define	disknet_grub_net_BOOTP_RFC1048_MAGIC_2	0x53
#define	disknet_grub_net_BOOTP_RFC1048_MAGIC_3	0x63

enum
  {
    disknet_grub_net_BOOTP_PAD = 0,
    disknet_grub_net_BOOTP_NETMASK = 1,
    disknet_grub_net_BOOTP_ROUTER = 3,
    disknet_grub_net_BOOTP_DNS = 6,
    disknet_grub_net_BOOTP_HOSTNAME = 12,
    disknet_grub_net_BOOTP_DOMAIN = 15,
    disknet_grub_net_BOOTP_ROOT_PATH = 17,
    disknet_grub_net_BOOTP_EXTENSIONS_PATH = 18,
    disknet_grub_net_DHCP_REQUESTED_IP_ADDRESS = 50,
    disknet_grub_net_DHCP_OVERLOAD = 52,
    disknet_grub_net_DHCP_MESSAGE_TYPE = 53,
    disknet_grub_net_DHCP_SERVER_IDENTIFIER = 54,
    disknet_grub_net_DHCP_PARAMETER_REQUEST_LIST = 55,
    disknet_grub_net_BOOTP_CLIENT_ID = 61,
    disknet_grub_net_DHCP_TFTP_SERVER_NAME = 66,
    disknet_grub_net_DHCP_BOOTFILE_NAME = 67,
    disknet_grub_net_BOOTP_CLIENT_UUID = 97,
    disknet_grub_net_BOOTP_END = 255
  };

struct disknet_grub_net_network_level_interface *
disknet_grub_net_configure_by_dhcp_ack (const char *name,
				struct disknet_grub_net_card *card,
				disknet_grub_net_interface_flags_t flags,
				const struct disknet_grub_net_bootp_packet *bp,
				grub_size_t size,
				int is_def, char **device, char **path);

grub_err_t
disknet_grub_net_add_ipv4_local (struct disknet_grub_net_network_level_interface *inf,
			 int mask);

void
disknet_grub_net_process_dhcp (struct disknet_grub_net_buff *nb,
		       struct disknet_grub_net_network_level_interface *iface);

int
disknet_grub_net_hwaddr_cmp (const disknet_grub_net_link_level_address_t *a,
		     const disknet_grub_net_link_level_address_t *b);
int
disknet_grub_net_addr_cmp (const disknet_grub_net_network_level_address_t *a,
		   const disknet_grub_net_network_level_address_t *b);


/*
  Currently supported adresses:
  IPv4:   XXX.XXX.XXX.XXX
  IPv6:   XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX
 */
#define disknet_grub_net_MAX_STR_ADDR_LEN sizeof ("XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX")

/*
  Currently suppoerted adresses:
  ethernet:   XX:XX:XX:XX:XX:XX
 */

#define disknet_grub_net_MAX_STR_HWADDR_LEN (sizeof ("XX:XX:XX:XX:XX:XX"))

void
disknet_grub_net_addr_to_str (const disknet_grub_net_network_level_address_t *target,
		      char *buf);
void
disknet_grub_net_hwaddr_to_str (const disknet_grub_net_link_level_address_t *addr, char *str);

grub_err_t
disknet_grub_env_set_net_property (const char *intername, const char *suffix,
                           const char *value, grub_size_t len);

void
disknet_grub_net_poll_cards (unsigned time, int *stop_condition);

void grub_bootp_init (void);
void grub_bootp_fini (void);

void disknet_grub_dns_init (void);
void disknet_grub_dns_fini (void);

static inline void
disknet_grub_net_network_level_interface_unregister (struct disknet_grub_net_network_level_interface *inter)
{
  inter->card->num_ifaces--;
  *inter->prev = inter->next;
  if (inter->next)
    inter->next->prev = inter->prev;
  inter->next = 0;
  inter->prev = 0;
}

void
disknet_grub_net_tcp_retransmit (void);

void
disknet_grub_net_link_layer_add_address (struct disknet_grub_net_card *card,
				 const disknet_grub_net_network_level_address_t *nl,
				 const disknet_grub_net_link_level_address_t *ll,
				 int override);
int
disknet_grub_net_link_layer_resolve_check (struct disknet_grub_net_network_level_interface *inf,
				   const disknet_grub_net_network_level_address_t *proto_addr);
grub_err_t
disknet_grub_net_link_layer_resolve (struct disknet_grub_net_network_level_interface *inf,
			     const disknet_grub_net_network_level_address_t *proto_addr,
			     disknet_grub_net_link_level_address_t *hw_addr);
grub_err_t
disknet_grub_net_dns_lookup (const char *name,
		     const struct disknet_grub_net_network_level_address *servers,
		     grub_size_t n_servers,
		     grub_size_t *naddresses,
		     struct disknet_grub_net_network_level_address **addresses,
		     int cache);
grub_err_t
disknet_grub_net_add_dns_server (const struct disknet_grub_net_network_level_address *s);
void
disknet_grub_net_remove_dns_server (const struct disknet_grub_net_network_level_address *s);

grub_err_t
disknet_grub_net_search_config_file (char *config);

grub_err_t
disknet_grub_net_fs_open (struct grub_file *file_out, const char *name);

extern char *disknet_grub_net_default_server;

#define disknet_grub_net_TRIES 40
#define disknet_grub_net_INTERVAL 400
#define disknet_grub_net_INTERVAL_ADDITION 20

#define VLANTAG_IDENTIFIER 0x8100

#endif /* ! disknet_grub_net_HEADER */
