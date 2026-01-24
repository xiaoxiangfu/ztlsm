// SPDX-License-Identifier: GPL-2.0-only
/*
 * Zero Trust Security Module
 *
 * Author: Zhi Li <lizhi1215@sina.com>
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/inetdevice.h>
#include <linux/timekeeping.h>
#include <linux/overflow.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/lsm_hooks.h>

// protocol type
#define ZTLSM_TRANSPORT_TCP 1
#define ZTLSM_TRANSPORT_UDP 2		  

// ip addresss type
#define ZTLSM_IP_ANY      0
#define ZTLSM_IP_NORMAL   1
#define ZTLSM_IP_LOCAL    2
#define ZTLSM_IP_INTERNAL 3
#define ZTLSM_IP_EXTERNAL 4

// port address type
#define ZTLSM_PORT_ANY            0
#define ZTLSM_PORT_EXACT          1
#define ZTLSM_PORT_PRIVILEGED     2
#define ZTLSM_PORT_UNPRIVILEGED   3

struct ztlsm_policy
{
  /* IP */
  __be32 src_ip;
  __be32 dst_ip;
  u8 src_mask;
  u8 dst_mask;
  u8 src_ip_type;
  u8 dst_ip_type;

  /* Port */
  __be16 src_port;
  __be16 dst_port;
  u8 src_port_type;
  u8 dst_port_type;

  /* Protocol */
  u8 trans_proto;

  /* Quota */
  u64 quota; // bytes per min
  spinlock_t quota_lock;
  struct list_head quota_list;
  
  /* Cached */
  u64 cached_size;
  
  /* link */
  struct list_head list;

  /* rcu */
  struct rcu_head rcu;
};

struct ztlsm_msg
{
  ktime_t ts;
  u64 size;
  struct list_head list;
};

struct ztlsm_five_tuple {
  __be32 sip, dip;
  __be16 sport, dport;
  u8 proto;
};

static LIST_HEAD(ztlsm_ipv4_policy_list);

static int resolve_ipv4(char* ip_str, __be32 *ip, u8 *mask)
{
  u8 addr[4];  // resolved 4 bytes for ip address
  int ret;
  char *mask_p;

  mask_p = strchr(ip_str, '/');
  if (mask_p)
    *mask_p++ = '\0';
  
  // call in4_pton to put ip string into 4 bytes array (net byte order)
  ret = in4_pton(ip_str, -1, addr, -1, NULL);
  if (ret != 1 ) {
    printk(KERN_ERR "ZT LSM: Invalid IP address: %s.\n", ip_str);
    return -EINVAL;
  }

  // translate 4 bytes array into integer
  memcpy(ip, addr, sizeof(__be32));

  // handle mask
  ret = 0;
  if (mask_p == NULL)
    *mask = 32;
  else if (*mask_p == '\0') {
    printk(KERN_WARNING "ZT LSM: in mask sub string, there is no number after '/'.\n");
    *mask = 32;
  } else {
    ret = kstrtou8(mask_p, 10, mask);
    if (ret)
      printk(KERN_ERR "ZT LSM: in resolve_ip, an error(%d) occured in kstrtou8.\n", ret);
  }

  return ret;
}

static int resolve_ipv4_ex(char *ip_str, __be32 *ip, u8 *mask, u8 *ip_type)
{
  if (strcmp(ip_str, "any")==0 ||
      strcmp(ip_str, "Any")==0 ||
      strcmp(ip_str, "ANY")==0) {
    *ip_type = ZTLSM_IP_ANY;
    return 0;
  }

  if (strcmp(ip_str, "local")==0 ||
      strcmp(ip_str, "Local")==0 ||
      strcmp(ip_str, "LOCAL")==0) {
    *ip_type = ZTLSM_IP_LOCAL;
    return 0;
  }

  if (strcmp(ip_str, "internal")==0 ||
      strcmp(ip_str, "Internal")==0 ||
      strcmp(ip_str, "INTERNAL")==0) {
    *ip_type = ZTLSM_IP_INTERNAL;
    return 0;
  }

  if (strcmp(ip_str, "external")==0 ||
      strcmp(ip_str, "External")==0 ||
      strcmp(ip_str, "EXTERNAL")==0) {
    *ip_type = ZTLSM_IP_EXTERNAL;
    return 0;
  }

  /* numeric IP */
  *ip_type = ZTLSM_IP_NORMAL;
  return resolve_ipv4(ip_str, ip, mask);
}

static int resolve_port_ex(const char* port_str, __be16 *port, u8 *port_type)
{
  int ret;
  u16 tmp;

  if (strcmp(port_str, "any")==0 ||
      strcmp(port_str, "Any")==0 ||
      strcmp(port_str, "ANY")==0) {
    *port_type = ZTLSM_PORT_ANY;
    return 0;
  }

  if (strcmp(port_str, "privileged")==0 ||
      strcmp(port_str, "Privileged")==0 ||
      strcmp(port_str, "PRIVILEGED")==0) {
    *port_type = ZTLSM_PORT_PRIVILEGED;
    return 0;
  }

  if (strcmp(port_str, "unprivileged")==0 ||
      strcmp(port_str, "Unprivileged")==0 ||
      strcmp(port_str, "UNPRIVILEGED")==0) {
    *port_type = ZTLSM_PORT_UNPRIVILEGED;
    return 0;
  }

  ret = kstrtou16(port_str, 10, &tmp);
  if (ret)
    return ret;
  
  *port = cpu_to_be16(tmp);
  *port_type = ZTLSM_PORT_EXACT;
  return ret;
}

static int resolve_proto(const char* proto_str, u8 *trans_proto)
{
  if (strncmp(proto_str, "TCP", 3) == 0 ||
      strncmp(proto_str, "Tcp", 3) == 0 ||
      strncmp(proto_str, "tcp", 3) == 0)
    *trans_proto = ZTLSM_TRANSPORT_TCP;
  else if (strncmp(proto_str, "UDP", 3) == 0 ||
	   strncmp(proto_str, "Udp", 3) == 0 ||
	   strncmp(proto_str, "udp", 3) == 0)
    *trans_proto = ZTLSM_TRANSPORT_UDP;
  else {
    printk(KERN_ERR "The Transport protocol string(%s) is wrong, which shall be either \"TCP\" or \"UDP\".\n", proto_str);
    *trans_proto = 0;
    return -1;
  }
  
  return 0;
}

static int resolve_bandwidth(char* bandwidth_str, u64 *bandwidth)
{
  u64 number, mul_n;
  int ret;
  char *p, unit;

  // skip digit number, get the unit representation
  p = bandwidth_str;
  while (isdigit(*p))
    p++;
  
  unit = *p;
  *p = '\0';

  // get the bandwidth number
  ret = kstrtoull(bandwidth_str, 10, &number);
  if (ret)
    return ret;

  // get multiple number
  ret = 0;
  switch (unit) {
  case '\0': // no suffix
    mul_n = 1ULL;
    break;
  case 'k':
  case 'K':
    mul_n = 1000ULL;
    break;
  case 'm':
  case 'M':
    mul_n = 1000000ULL;
    break;
  case 'g':
  case 'G':
    mul_n = 1000000000ULL;
    break;
  default:
    mul_n = 1ULL;
    ret = -EINVAL;
    printk(KERN_ERR "ZT LSM: the suffix of bandwidth(%s) is not K/M/G.\n", bandwidth_str);
    break;
  }

  // calculate the bandwidth number
  if (ret == 0 && mul_n != 1ULL && check_mul_overflow(number, mul_n, &number)) {
    printk(KERN_WARNING "ZT LSM: bandwidth(%s) is overflow.\n", bandwidth_str);
    ret = -ERANGE;
  }

  *bandwidth = number;

  return ret;
}

static int policy_add(struct ztlsm_policy *src)
{
  struct ztlsm_policy *pol;

  pol = kzalloc(sizeof(struct ztlsm_policy), GFP_KERNEL);
  if (!pol)
    return -ENOMEM;

  memcpy(pol, src, sizeof(struct ztlsm_policy));
  spin_lock_init(&pol->quota_lock);
  INIT_LIST_HEAD(&pol->quota_list);
  pol->cached_size = 0;
  INIT_LIST_HEAD(&pol->list);

  list_add_tail_rcu(&pol->list, &ztlsm_ipv4_policy_list);

  return 0;
}

static ssize_t policy_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos);
static ssize_t policy_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos);

static const struct file_operations policy_fops =
  {
    .owner = THIS_MODULE,
    .write = policy_write,
    .read  = policy_read,
  };

static void policy_rcu_free(struct rcu_head *rcu)
{
  struct ztlsm_policy *pol = container_of(rcu, struct ztlsm_policy, rcu);
  struct ztlsm_msg *entry, *tmp;

  list_for_each_entry_safe(entry, tmp, &pol->quota_list, list) {
    list_del(&entry->list);
    kfree(entry);
  }
  kfree(pol);
}

static void policy_clear(void)
{
  struct ztlsm_policy *pol, *tmp;

  list_for_each_entry_safe(pol, tmp, &ztlsm_ipv4_policy_list, list) {
    list_del_rcu(&pol->list);
    call_rcu(&pol->rcu, policy_rcu_free);
  }
}

static ssize_t policy_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos)
{
  char *buf, *line;
  size_t len;
  int ret = 0;

  if (count==0) {
    /* No new policies, just clear old ones. This is dangerous, because
       ztlsm uses white list, no policies means all network connections
       are denied.
     */ 
    policy_clear();
    return 0;
  }
  
  buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
  if (!buf)
    return -ENOMEM;

  len = min(count, (size_t)(PAGE_SIZE-1));
  if (copy_from_user(buf, user_buf, len)) {
    kfree(buf);
    printk(KERN_ERR "copy from user failed.\n");
    return -EFAULT;
  }

  // before write new policies, clear old policies.
  policy_clear();
  
  buf[len] = '\0';
  line = buf;
  while (line) {
    struct ztlsm_policy pol = {};
    char *p = line, *orig = line;
    char *next, *tok;
    
    next = strchr(p, '\n');
    if (next)
      *next++ = '\0';

    // erase beginning blanks and ending blanks
    p = strstrip(p);
    if (strlen(p) == 0) {
      line = next;
      continue;
    }

    // handle 1st field: source ip
    tok = strsep(&p, " ");
    if (!tok)
      goto next_line;

    ret = resolve_ipv4_ex(tok, &pol.src_ip, &pol.src_mask, &pol.src_ip_type);
    if (ret)
      goto next_line;

    printk(KERN_INFO "src: ip=0x%x, mask=%hhu, type=%hhu.\n", pol.src_ip, pol.src_mask, pol.src_ip_type);
    
    // handle 2nd field: source port
    tok = strsep(&p, " ");
    if (!tok)
      goto next_line;

    ret = resolve_port_ex(tok, &pol.src_port, &pol.src_port_type);
    if (ret)
      goto next_line;

    printk(KERN_INFO "src: port=0x%hx, type=%hhu.\n", pol.src_port, pol.src_port_type);
    
    // handle 3rd field: dest ip
    tok = strsep(&p, " ");
    if (!tok)
      goto next_line;

    ret = resolve_ipv4_ex(tok, &pol.dst_ip, &pol.dst_mask, &pol.dst_ip_type);
    if (ret)
      goto next_line;

    printk(KERN_INFO "dst: ip=0x%x, mask=%hhu, type=%hhu.\n", pol.dst_ip, pol.dst_mask, pol.dst_ip_type);
    // handle 4th field: dest port
    tok = strsep(&p, " ");
    if (!tok)
      goto next_line;

    ret = resolve_port_ex(tok, &pol.dst_port, &pol.dst_port_type);
    if (ret)
      goto next_line;

    printk(KERN_INFO "dst: port=0x%hx, type=%hhu.\n", pol.dst_port, pol.dst_port_type);
    
    // handle 5th field: protocol
    tok = strsep(&p, " ");
    if (!tok)
      goto next_line;

    ret = resolve_proto(tok, &pol.trans_proto);
    if (ret)
      goto next_line;

    printk(KERN_INFO "protocol=%hhu.\n", pol.trans_proto);
    
    // handle 6th field: quota
    tok = p;
    if (!tok)
      goto next_line;

    ret = resolve_bandwidth(tok, &pol.quota);
    if (ret)
      goto next_line;

    printk(KERN_INFO "quota=%llu.\n", pol.quota);

    // add policy into list
    ret = policy_add(&pol);
    if (ret)
      printk(KERN_ERR "ZT LSM: failed to add policy, ret=%d.\n", ret);
    
  next_line:
    line = next;
    if (ret)
      printk(KERN_WARNING "ZT LSM: The policy line which is started with \"%s\" is invalid.\n", orig);
  }

  kfree(buf);

  // update file position, it is useless, but it is standard action in write function.
  *ppos += len;
  
  return len;
}

static int ipv4_to_str(char *buf, size_t len, __be32 ip, u8 mask, u8 type)
{
  switch (type) {
  case ZTLSM_IP_ANY:
    return scnprintf(buf, len, "any");
    
  case ZTLSM_IP_LOCAL:
    return scnprintf(buf, len, "local");
    
  case ZTLSM_IP_INTERNAL:
    return scnprintf(buf, len, "internal");
    
  case ZTLSM_IP_EXTERNAL:
    return scnprintf(buf, len, "external");
    
  case ZTLSM_IP_NORMAL:
    if (mask==32)
      return scnprintf(buf, len, "%pI4", &ip);
    else
      return scnprintf(buf, len, "%pI4/%u", &ip, mask);
    
  default:
    return scnprintf(buf, len, "unknown");
  }
}

static int port_to_str(char *buf, size_t len, __be16 port, u8 type)
{
  switch (type) {
  case ZTLSM_PORT_ANY:
    return scnprintf(buf, len, "any");
    
  case ZTLSM_PORT_PRIVILEGED:
    return scnprintf(buf, len, "privileged");
    
  case ZTLSM_PORT_UNPRIVILEGED:
    return scnprintf(buf, len, "unprivileged");
    
  case ZTLSM_PORT_EXACT:
    return scnprintf(buf, len, "%u", ntohs(port));
    
  default:
    return scnprintf(buf, len, "unknown");
  }
}

static ssize_t policy_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
  struct ztlsm_policy *pol;
  char *buf, *buf2;
  ssize_t len=0;
  ssize_t ret;
  char *sip, *dip, *sport, *dport;

  if (*ppos > 0) //only support to read from start position
    return 0;

  buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
  if (!buf)
    return -ENOMEM;

  buf2 = kmalloc(64+64+32+32, GFP_KERNEL);
  if (!buf2) {
    kfree(buf);
    return -ENOMEM;
  }

  sip = buf2;
  dip = buf2+64;
  sport = buf2+64+64;
  dport = buf2+64+64+32;

  rcu_read_lock();
  list_for_each_entry_rcu(pol, &ztlsm_ipv4_policy_list, list) {
    ipv4_to_str(sip, 64, pol->src_ip, pol->src_mask, pol->src_ip_type);
    ipv4_to_str(dip, 64, pol->dst_ip, pol->dst_mask, pol->dst_ip_type);
    port_to_str(sport, 32, pol->src_port, pol->src_port_type);
    port_to_str(dport, 32, pol->dst_port, pol->dst_port_type);
    
    len += scnprintf(buf+len, PAGE_SIZE-len,
		     "%s %s %s %s %s %llu\n",
		     sip, sport, dip, dport, 
		     pol->trans_proto == ZTLSM_TRANSPORT_TCP ? "TCP" : "UDP",
		     pol->quota);

    if (len >= PAGE_SIZE)
      break;
  }
  rcu_read_unlock();
  
  ret = simple_read_from_buffer(user_buf, count, ppos, buf, len);
  kfree(buf);
  kfree(buf2);
  return ret;
}

static bool ipv4_prefix_match(__be32 net, u8 mask, __be32 ip)
{
  __be32 mask_be;

  if (mask == 0)
    return true;

  mask_be = cpu_to_be32(~0U << (32 - mask));
  return (net & mask_be) == (ip & mask_be);
}

static inline bool ipv4_is_rfc1918(__be32 ip)
{
  /* 10.0.0.0/8 */
  if (ipv4_is_private_10(ip))
    return true;

  /* 172.16.0.0/12 */
  if (ipv4_is_private_172(ip))
    return true;

  /* 192.168.0.0/16 */
  if (ipv4_is_private_192(ip))
    return true;

  return false;
}

static bool ipv4_is_local_lan(__be32 ip)
{
  struct net_device *dev;
  struct in_device *in_dev;
  struct in_ifaddr *ifa;

  rcu_read_lock();
  for_each_netdev(&init_net, dev) {
    in_dev = __in_dev_get_rcu(dev);
    if (!in_dev)
      continue;

    for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
      if (ipv4_prefix_match(ifa->ifa_address, ifa->ifa_prefixlen, ip)) {
        rcu_read_unlock();
        return true;
      }
    }
  }
  rcu_read_unlock();
  return false;
}

static inline bool ipv4_is_reserved(__be32 ip)
{
  /* 240.0.0.0/4 */
  return ipv4_prefix_match(cpu_to_be32(0xF0000000), 4, ip);
}

/* The external ipv4 address is a routable public IPv4 unicast address */
static bool ipv4_is_external(__be32 ip)
{
  if (ipv4_is_zeronet(ip))
    return false;

  if (ipv4_is_loopback(ip))
    return false;

  if (ipv4_is_linklocal_169(ip))
    return false;

  if (ipv4_is_multicast(ip))
    return false;

  if (ipv4_is_reserved(ip))
    return false;

  if (ipv4_is_rfc1918(ip))
    return false;

  if (ipv4_is_local_lan(ip))
    return false;

  return true;
}

static bool ipv4_match(const struct ztlsm_policy *pol, __be32 ip, bool is_src)
{
  u8 type;
  __be32 net;
  u8 mask;

  if (is_src) {
    type = pol->src_ip_type;
    net  = pol->src_ip;
    mask = pol->src_mask;
  } else {
    type = pol->dst_ip_type;
    net  = pol->dst_ip;
    mask = pol->dst_mask;
  }

  switch (type) {
  case ZTLSM_IP_ANY:
    return true;

  case ZTLSM_IP_NORMAL:
    return ipv4_prefix_match(net, mask, ip);

  case ZTLSM_IP_INTERNAL:
    return ipv4_is_rfc1918(ip);

  case ZTLSM_IP_EXTERNAL:
    return ipv4_is_external(ip);

  case ZTLSM_IP_LOCAL:
    return ipv4_is_local_lan(ip);

  default:
    printk(KERN_ERR "The policy ip type is undefined.\n");
    return false;
  }
}

static bool port_match(const struct ztlsm_policy *pol, __be16 port, bool is_src)
{
  u8 type;
  __be16 ref;

  if (is_src) {
    type = pol->src_port_type;
    ref  = pol->src_port;
  } else {
    type = pol->dst_port_type;
    ref  = pol->dst_port;
  }

  switch (type) {
  case ZTLSM_PORT_ANY:
    return true;

  case ZTLSM_PORT_PRIVILEGED:
    return ntohs(port) < 1024;

  case ZTLSM_PORT_UNPRIVILEGED:
    return ntohs(port) >= 1024;

  case ZTLSM_PORT_EXACT:
    return ref == port;

  default:
    printk(KERN_ERR "The policy port type is undefined.\n");
    return false;
  }
}

static inline bool proto_match(const struct ztlsm_policy *pol, u8 proto)
{
  return pol->trans_proto == proto;
}


static bool policy_match(const struct ztlsm_policy *pol, struct ztlsm_five_tuple *ft)
{
  if (!ipv4_match(pol, ft->sip, true))
    return false;

  if (!port_match(pol, ft->sport, true))
    return false;

  if (!ipv4_match(pol, ft->dip, false))
    return false;

  if (!port_match(pol, ft->dport, false))
    return false;

  if (!proto_match(pol, ft->proto))
    return false;

  return true;
}

static struct ztlsm_policy* get_matched_policy_core(struct ztlsm_five_tuple *ft)
{
  struct ztlsm_policy *pol;
  
  list_for_each_entry_rcu(pol, &ztlsm_ipv4_policy_list, list) {
    if (policy_match(pol, ft)) {
      return pol;
    }
  }
  return NULL;
}

static struct ztlsm_policy* get_matched_policy(struct ztlsm_five_tuple *ft)
{
  struct ztlsm_policy *pol;
  rcu_read_lock();
  pol = get_matched_policy_core(ft);
  rcu_read_unlock();
  return pol;
}

static int assign_five_tuple(struct socket *sock, struct msghdr *msg, struct ztlsm_five_tuple *ft, int is_recv)
{
  struct sock *sk;
  struct sockaddr_in *sin;
  struct inet_sock *inet;
  
  if (!sock || !sock->sk)
    return 1;

  sk = sock->sk;
  
  /* Currently only support IPv4 */
  if (sk->sk_family != AF_INET)
    return 1;

  inet = inet_sk(sk);
  
  if (sk->sk_protocol == IPPROTO_TCP)
    ft->proto = ZTLSM_TRANSPORT_TCP;
  else if (sk->sk_protocol == IPPROTO_UDP)
    ft->proto = ZTLSM_TRANSPORT_UDP;
  else
    return 1;

  if (!msg || !msg->msg_name) {
    /* For connected socket (TCP or connected UDP), msg_name == NULL
       is normal.
    */
    if (is_recv) {
      /* peer -> local */
      ft->sip = inet->inet_daddr;
      ft->sport = inet->inet_dport;
      ft->dip = inet->inet_rcv_saddr;
      ft->dport = inet->inet_sport;
    } else {
      /* local -> peer */
      ft->sip = inet->inet_rcv_saddr;
      ft->sport = inet->inet_sport;
      ft->dip = inet->inet_daddr;
      ft->dport = inet->inet_dport;
    }
  } else {
    /* For unconnected socket, msg_name is not NULL */
    sin = (struct sockaddr_in *)msg->msg_name;

    if (is_recv) {
      /* peer side is source */
      ft->sip   = sin->sin_addr.s_addr;
      ft->sport = sin->sin_port;
    
      /* this side is destination */
      ft->dip   = inet->inet_rcv_saddr;
      ft->dport = inet->inet_sport;
    } else {
      /* this side is source */
      ft->sip   = inet->inet_rcv_saddr;
      ft->sport = inet->inet_sport;
  
      /* peer side is destination */
      ft->dip   = sin->sin_addr.s_addr;
      ft->dport = sin->sin_port;
    }
  }

  return 0;
}

static int check_quota(struct ztlsm_policy *pol, int size)
{
  struct ztlsm_msg *entry, *tmp;
  ktime_t now;
  s64 delta_ns;
  u64 window_ns = 60LL * NSEC_PER_SEC;
  u64 total;
  int ret;
  
  if (!pol || size <= 0)
    return 0;

  now = ktime_get();
  spin_lock(&pol->quota_lock);

  // iterate from rear
  list_for_each_entry_safe_reverse(entry, tmp, &pol->quota_list, list) {
    delta_ns = ktime_to_ns(ktime_sub(now, entry->ts));

    // alread in the time window
    if (delta_ns <= window_ns)
      break;

    // outside the time window
    list_del(&entry->list);
    pol->cached_size -= entry->size;
    kfree(entry);
  }

  // judge size
  total = pol->cached_size + size;
  if (total > pol->quota) {
    ret = -EACCES;
    goto out;
  }

  // record the entry
  entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
  if (!entry) {
    // no memory for new entry, just allow the operation
    ret = 0;
    goto out;
  }

  entry->ts = now;
  entry->size = size;

  // add the new entry into policy's quota list
  list_add(&entry->list, &pol->quota_list);

  // add cached size
  pol->cached_size += size;

  ret = 0;
 out:
  spin_unlock(&pol->quota_lock);
  return ret;
}

static int match_and_check(struct ztlsm_five_tuple *ft, int size)
{
  struct ztlsm_policy *pol;
  int ret;
  
  rcu_read_lock();
  /* find policy */
  pol = get_matched_policy_core(ft);
  if (!pol) {
    rcu_read_unlock();
    return -EACCES;
  }
  /* check policy's quota */
  ret = check_quota(pol, size);
  rcu_read_unlock();

  return ret;
}

static int ztlsm_socket_connect(struct socket *sock, struct sockaddr *addr, int addrlen)
{
  struct sock *sk;
  struct ztlsm_policy *pol;
  struct sockaddr_in *sin;
  struct ztlsm_five_tuple ft;

  if (!sock || !addr)
    return 0;

  sk = sock->sk;
  
  /* Currently only support IPv4*/
  if (!sk || sk->sk_family != AF_INET)
    return 0;

  if (sk->sk_protocol == IPPROTO_TCP)
    ft.proto = ZTLSM_TRANSPORT_TCP;
  else if (sk->sk_protocol == IPPROTO_UDP)
    ft.proto = ZTLSM_TRANSPORT_UDP;
  else
    return 0;

  /* This side is source */
  ft.sip   = inet_sk(sk)->inet_saddr;
  ft.sport = inet_sk(sk)->inet_sport;

  /* Peer side is dest */
  sin = (struct sockaddr_in *)addr;
  ft.dip   = sin->sin_addr.s_addr;
  ft.dport = sin->sin_port;

  pol = get_matched_policy(&ft);
  if (pol)
    return 0;
  else {
    printk(KERN_WARNING "ZT LSM: connection denied\n");
    return -EACCES;
  }
}

static int ztlsm_socket_accept(struct socket *sock, struct socket *newsock)
{
  struct sock *sk;
  struct ztlsm_policy *pol;
  struct ztlsm_five_tuple ft;

  if (!newsock)
    return 0;

  sk = newsock->sk;
  
  /* Currently only support IPv4 */
  if (!sk || sk->sk_family != AF_INET)
    return 0;

  if (sk->sk_protocol == IPPROTO_TCP)
    ft.proto = ZTLSM_TRANSPORT_TCP;
  else if (sk->sk_protocol == IPPROTO_UDP)
    ft.proto = ZTLSM_TRANSPORT_UDP;
  else
    return 0;
      
  /* Peer side is source */
  ft.sip   = inet_sk(sk)->inet_daddr;
  ft.sport = inet_sk(sk)->inet_dport;

  /* this side is destination */
  ft.dip   = inet_sk(sk)->inet_rcv_saddr;
  ft.dport = inet_sk(sk)->inet_sport;

  pol = get_matched_policy(&ft);
  if (pol)
    return 0;
  else {
    printk(KERN_WARNING "ZT LSM: connection denied\n");
    return -EACCES;
  }
}

static int ztlsm_socket_sendmsg(struct socket *sock,
                                struct msghdr *msg,
                                int size)
{
  struct ztlsm_five_tuple ft;

  if ( assign_five_tuple(sock, msg, &ft, 0) != 0 )
    // 5 tuple can not be constructed
    return 0;
  
  return match_and_check(&ft, size);
}

static int ztlsm_socket_recvmsg(struct socket *sock,
                                struct msghdr *msg,
                                int size,
                                int flags)
{
  struct ztlsm_five_tuple ft;

  if ( assign_five_tuple(sock, msg, &ft, 1) != 0 )
    // 5 tuple can not be constructed
    return 0;
  
  return match_and_check(&ft, size);
}

static int __init ztlsm_files_init(void)
{
  int ret;
  static struct dentry *ztlsm_dir;
  static struct dentry *policy_file;
  
  printk(KERN_INFO "ZT LSM: files init.\n");

  // create securityfs directory: /sys/kernel/security/ztlsm
  ztlsm_dir = securityfs_create_dir("ztlsm", NULL);
  if (IS_ERR(ztlsm_dir)) {
    ret = PTR_ERR(ztlsm_dir);
    printk(KERN_ERR "ZT LSM: Failed to create ztlsm dir. The error is %d.\n", ret);
    return ret;
  }

  // create securityfs file: /sys/kernel/security/ztlsm/policy
  policy_file = securityfs_create_file("policy", 0644, ztlsm_dir, NULL, &policy_fops);
  if (IS_ERR(policy_file)) {
    ret = PTR_ERR(policy_file);
    printk(KERN_ERR "ZT LSM: Failed to create policy file. The error is %d.\n", ret);
    securityfs_remove(ztlsm_dir);
    return ret;
  }

  return 0;
}

static int policy_add_default_allow(void)
{
  struct ztlsm_policy pol = {};
  int ret;
  
  pol.src_ip_type = ZTLSM_IP_ANY;
  pol.dst_ip_type = ZTLSM_IP_ANY;
  pol.src_port_type = ZTLSM_PORT_ANY;
  pol.dst_port_type = ZTLSM_PORT_ANY;
  pol.trans_proto = ZTLSM_TRANSPORT_TCP;
  pol.quota = ULLONG_MAX;

  ret = policy_add(&pol);
  if (ret) return ret;

  pol.trans_proto = ZTLSM_TRANSPORT_UDP;

  ret = policy_add(&pol);
  if (ret) return ret;

  return 0;
}

static const struct lsm_id ztlsm_id = {
  .name = "ztlsm",
  .id = LSM_ID_ZTLSM,
};

static struct security_hook_list ztlsm_hooks[] __ro_after_init = {
  LSM_HOOK_INIT(socket_connect, ztlsm_socket_connect),
  LSM_HOOK_INIT(socket_accept, ztlsm_socket_accept),
  LSM_HOOK_INIT(socket_sendmsg, ztlsm_socket_sendmsg),
  LSM_HOOK_INIT(socket_recvmsg, ztlsm_socket_recvmsg)
};

static int __init ztlsm_init(void)
{
  int ret;
  security_add_hooks(ztlsm_hooks,
		     ARRAY_SIZE(ztlsm_hooks),
		     &ztlsm_id);
  ret = ztlsm_files_init();
  if (ret) return ret;

  ret = policy_add_default_allow();
  if (ret) return ret;

  return 0;
}

DEFINE_LSM(ztlsm) = {
	.name = "ztlsm",
	.init = ztlsm_init,
};
