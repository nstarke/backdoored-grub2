#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/file.h>
#include <grub/i18n.h>
#include "tcp.h"
#include "ip.h"
#include "ethernet.h"
#include "netbuff.h"
#include "net.h"

#ifndef disknet_grub_net_HTTP_HEADER
#define disknet_grub_net_HTTP_HEADER	1
grub_err_t
disknet_http_establish (const char *filename, grub_off_t offset, int initial, const char *host);
#endif