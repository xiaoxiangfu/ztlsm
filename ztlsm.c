// SPDX-License-Identifier: GPL
/*
 * Zero Trust Security Module
 *
 * Author: Zhi Li <lizhi1215@sina.com>
 */

/*
 * ===========================
 * Known Limitations / 教学说明
 * ===========================
 *
 * 本模块为教学和研究用途，仍然存在如下已知限制与设计权衡：
 *
 * 1. RCU 与 update_lock 并非严格的 RCU 原子替换模型
 * ---------------------------------------------------
 * policy_clear() 使用 list_del_rcu + call_rcu()，
 * 读路径使用 list_for_each_entry_rcu()，
 * 但策略更新阶段使用普通 list_for_each_entry + list_add_tail_rcu。
 *
 * 当前实现是安全的，但并未采用“指针级整体替换”的标准 RCU 设计模式，
 * 该实现适合教学演示 RCU 的基本用法，但不属于严格的生产级 RCU 设计。
 *
 *
 * 2. 流量限额算法时间复杂度为 O(n)
 * -----------------------------------
 * check_quota() 使用链表保存一分钟内的每个数据包。
 * 在高流量场景下，quota_list 可能变得很大，
 * 每次检查都需要线性遍历并清理超时节点。
 *
 * 该实现用于展示滑动时间窗口思想，但不适用于高吞吐量生产环境。
 *
 *
 * 3. ipv4_is_local_lan() 在 fast path 中遍历所有网络设备
 * -------------------------------------------------------
 * 该函数在每次策略匹配时都会遍历所有 net_device 和 ifaddr。
 * 在高频网络场景下会带来明显性能损耗。
 *
 * 更优实现应使用缓存
 *
 * 4. policy_read() 仅支持最多 PAGE_SIZE 字节的策略输出
 * -----------------------------------------------------
 * 若策略过多，将被截断。
 * 教学场景中可接受，但非可扩展设计。
 *
 *
 * 5. 空写入策略 (echo "" > policy) 会清空所有策略
 * --------------------------------------------------
 * 本模块采用白名单模型。
 * 如果管理员误清空策略，将导致所有网络连接被拒绝。
 *
 * 此行为在教学场景用于强调“默认拒绝”的安全模型，
 * 但在生产系统中应避免此风险。
 *
 *
 * 6. 未实现 IPv6 支持
 * -------------------
 * 当前仅支持 AF_INET。
 *
 *
 * 本模块目标是展示：
 * - LSM hook 使用方式
 * - 五元组匹配设计
 * - RCU + spinlock 混合并发模型
 * - 基于滑动窗口的限流思路
 *
 * 并非生产级网络防火墙实现。
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

/*=============
 * 协议类型
 *=============*/
#define ZTLSM_TRANSPORT_TCP 1
#define ZTLSM_TRANSPORT_UDP 2		  

/*=============
 *IP地址类型
 *=============*/
// 任何IP地址
#define ZTLSM_IP_ANY      0

// 普通IP地址，xxx.xxx.xxx.xxx
#define ZTLSM_IP_NORMAL   1

// 局域网IP地址，与本机网络接口处于同一个网段，比如本地地址是
// 192.168.1.32/24， 局域网IP地址是192.168.1.xxx
#define ZTLSM_IP_LOCAL    2

// 内部IP地址，RFC 1918中定义了3种私有地址：10.0.0.0/8、
// 172.16.0.0/12和192.168.0.0/16
#define ZTLSM_IP_INTERNAL 3

// 外部地址，非内部地址，非局域网地址，非广播地址...
#define ZTLSM_IP_EXTERNAL 4

/*===================
 * port address type
 *===================*/
// 任何端口
#define ZTLSM_PORT_ANY            0

// 以数字定义的端口，比如80
#define ZTLSM_PORT_EXACT          1

// 小于1024的端口，需要特权才能使用
#define ZTLSM_PORT_PRIVILEGED     2

// 大于等于1024的端口，不需要特权
#define ZTLSM_PORT_UNPRIVILEGED   3

/* ============================
 * 策略规则
 * ============================*/
struct ztlsm_policy
{
  /* IP */
  __be32 src_ip;
  __be32 dst_ip;
  u8 src_mask; 
  u8 dst_mask;
  u8 src_ip_type;
  u8 dst_ip_type;

  /* 端口 */
  __be16 src_port;
  __be16 dst_port;
  u8 src_port_type;
  u8 dst_port_type;

  /* 协议: TCP/UDP */
  u8 trans_proto;

  /* 流量 */
  // 每分钟流量的限额（字节）
  u64 quota;
  // 用于操作quota_list的锁
  spinlock_t quota_lock;
  // 一分钟内的符合本条规则的消息被串联在quota_list作为表头
  // 的链表中，表中每个节点的类型是ztlsm_msg。
  struct list_head quota_list;
  
  /* 一分钟内的符合本条规则的消息的总数据量 */
  u64 cached_size;
  
  // 所有ztlsm_policy实例被串联成一个链表，表中的节点使用
  // list串联。 */
  struct list_head list;

  /* rcu使用来使用call_rcu函数延迟回收内存的 */
  struct rcu_head rcu;
};

// 网络包，用ztlsm_policy中的quota_list串联
struct ztlsm_msg
{
  // 网络包发生的时间
  ktime_t ts;
  // 网络包的数据量（字节）
  u64 size;
  // 链表指针
  struct list_head list;
};

// 网络五元组，用于匹配ztlsm_policy
struct ztlsm_five_tuple {
  __be32 sip, dip;
  __be16 sport, dport;
  u8 proto;
};

// 包含所有策略的链表的表头
static LIST_HEAD(ztlsm_ipv4_policy_list);

// 用于更新策略指针的自旋锁
static DEFINE_SPINLOCK(update_lock);
/*
 * 解析IP字符串，得到代表IP地址的整数和子网掩码
 */
static int resolve_ipv4(char* ip_str, __be32 *ip, u8 *mask)
{
  u8 addr[4];  // resolved 4 bytes for ip address
  int ret;
  char *mask_p;

  // 找到标记子网掩码的位置，比如192.168.16.130/24
  mask_p = strchr(ip_str, '/');
  if (mask_p)
    *mask_p++ = '\0';
  
  // 将IP字符串传唤为网络序整数数组
  ret = in4_pton(ip_str, -1, addr, -1, NULL);
  if (ret != 1 ) {
    printk(KERN_ERR "ZT LSM: Invalid IP address: %s.\n", ip_str);
    return -EINVAL;
  }

  // 将整数数组转换为整数
  memcpy(ip, addr, sizeof(__be32));

  // 处理子网掩码
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

/*
 * 解析IP字符串，得到IP类型、IP地址和子网掩码
 */
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

/*
 * 解析端口字符串，得到端口数字和端口类型
 */
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

/*
 * 解析协议
 */
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

/*
 * 解析带宽
 */
static int resolve_bandwidth(char* bandwidth_str, u64 *bandwidth)
{
  u64 number, mul_n;
  int ret;
  char *p, unit;

  // 跳过数字，得到数量单位
  p = bandwidth_str;
  while (isdigit(*p))
    p++;
  
  unit = *p;
  *p = '\0';

  // 得到带宽数字
  ret = kstrtoull(bandwidth_str, 10, &number);
  if (ret)
    return ret;

  // 计算单位所代表的数字
  ret = 0;
  switch (unit) {
  case '\0': // 没有单位
    mul_n = 1ULL;
    break;
  case 'k':
  case 'K': // K代表千
    mul_n = 1000ULL;
    break;
  case 'm':
  case 'M': // M代表百万
    mul_n = 1000000ULL;
    break;
  case 'g':
  case 'G': // G代表十亿
    mul_n = 1000000000ULL;
    break;
  default:
    mul_n = 1ULL;
    ret = -EINVAL;
    printk(KERN_ERR "ZT LSM: the suffix of bandwidth(%s) is not K/M/G.\n", bandwidth_str);
    break;
  }

  // 计算以字节计数的实际带宽数量
  if (ret == 0 && mul_n != 1ULL && check_mul_overflow(number, mul_n, &number)) {
    printk(KERN_WARNING "ZT LSM: bandwidth(%s) is overflow.\n", bandwidth_str);
    ret = -ERANGE;
  }

  *bandwidth = number;

  return ret;
}

/*
 * 将一条新策略加入全局的策略列表之中，由于src变量所指向的空间位于栈空间中，
 * 此处需要申请内存。
 */
static int policy_add(struct ztlsm_policy *src, struct list_head *head)
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

  list_add_tail_rcu(&pol->list, head);

  return 0;
}

/*
 * 释放一条策略
 */
static void policy_rcu_free(struct rcu_head *rcu)
{
  struct ztlsm_policy *pol = container_of(rcu, struct ztlsm_policy, rcu);
  struct ztlsm_msg *entry, *tmp;

  // 释放策略的消息缓冲
  list_for_each_entry_safe(entry, tmp, &pol->quota_list, list) {
    list_del(&entry->list);
    kfree(entry);
  }
  
  // 释放策略本身
  kfree(pol);
}

/*
 * 释放所有的策略
 */
static void policy_clear(void)
{
  struct ztlsm_policy *pol, *tmp;

  list_for_each_entry_safe(pol, tmp, &ztlsm_ipv4_policy_list, list) {
    list_del_rcu(&pol->list);
    call_rcu(&pol->rcu, policy_rcu_free);
  }
}

/*
 * securityfs中的policy文件的写入函数
 */
static ssize_t policy_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos)
{
  char *buf, *line;
  size_t len;
  int ret = 0;
  struct list_head tmp_head;
  bool policy_is_good = false;
  
  if (count==0) {
    /*
     * 没有新策略，只清除就策略，这样做是危险的，因为ztlsm使用白名单，没有策略意味着
     * 所有的网络连接都被禁止。
     */
    policy_clear();
    return 0;
  }

  /* 申请一页的缓存，这意味着用户写入的策略最多使用4096字节 */
  buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
  if (!buf)
    return -ENOMEM;

  // 将要写入的内容从用户态复制到内核态
  len = min(count, (size_t)(PAGE_SIZE-1));
  if (copy_from_user(buf, user_buf, len)) {
    kfree(buf);
    printk(KERN_ERR "copy from user failed.\n");
    return -EFAULT;
  }

  INIT_LIST_HEAD(&tmp_head);
  buf[len] = '\0';
  line = buf;
  while (line) {
    struct ztlsm_policy pol = {};
    char *p = line, *orig = line;
    char *next, *tok;

    // 找到一行的结尾
    next = strchr(p, '\n');
    if (next)
      *next++ = '\0';

    // 删除开始和结尾的空格
    p = strstrip(p);
    if (strlen(p) == 0) { // 空行
      line = next;
      continue;
    }

    // 处理第一个域：源IP地址
    tok = strsep(&p, " ");
    if (!tok)
      goto next_line;

    ret = resolve_ipv4_ex(tok, &pol.src_ip, &pol.src_mask, &pol.src_ip_type);
    if (ret)
      goto next_line;

    // 处理第二个域：源端口
    tok = strsep(&p, " ");
    if (!tok)
      goto next_line;

    ret = resolve_port_ex(tok, &pol.src_port, &pol.src_port_type);
    if (ret)
      goto next_line;

    // 处理第三个域：目的IP地址
    tok = strsep(&p, " ");
    if (!tok)
      goto next_line;

    ret = resolve_ipv4_ex(tok, &pol.dst_ip, &pol.dst_mask, &pol.dst_ip_type);
    if (ret)
      goto next_line;

    // 处理第四个域：目的端口
    tok = strsep(&p, " ");
    if (!tok)
      goto next_line;

    ret = resolve_port_ex(tok, &pol.dst_port, &pol.dst_port_type);
    if (ret)
      goto next_line;

    // 处理第五个域：协议类型
    tok = strsep(&p, " ");
    if (!tok)
      goto next_line;

    ret = resolve_proto(tok, &pol.trans_proto);
    if (ret)
      goto next_line;

    // 处理第六个域：带宽容量
    tok = p;
    if (!tok)
      goto next_line;

    ret = resolve_bandwidth(tok, &pol.quota);
    if (ret)
      goto next_line;

    // 将策略加入临时策略列表
    ret = policy_add(&pol, &tmp_head);
    if (ret) {
      printk(KERN_ERR "ZT LSM: failed to add policy, ret=%d.\n", ret);
      goto next_line;
    }
    
    line = next;
    policy_is_good = true;
    continue;
  next_line:
    printk(KERN_WARNING "ZT LSM: The policy line which is started with \"%s\" is invalid.\n", orig);
    policy_is_good = false;
    break;
  }

  kfree(buf);

  // 更新文件写入位置，这是无用操作，只是标准的文件写入处理逻辑。
  // 这个文件写入操作函数不支持接续式写入，即先写入一部分，再写入一部分，
  // 这个文件写入操作函数要求必须一次性写入所有策略，因为每次写入都会将
  // 前面写入的策略清除。
  *ppos += len;

  struct ztlsm_policy *tmp1, *tmp2;
  if (policy_is_good) {
    // 写入新策略前，清除旧策略。这意味着每次更新策略都是推倒重来，而不是渐进式更新。
    spin_lock(&update_lock);
    policy_clear();
    list_for_each_entry(tmp1, &tmp_head, list) {
      list_add_tail_rcu(&tmp1->list, &ztlsm_ipv4_policy_list);
    }
    spin_unlock(&update_lock);
  } else {
    // 输入的策略有错，释放之前已经申请的策略所占用的空间
    
    // 清除已经加入临时策略列表的策略
    list_for_each_entry_safe(tmp1, tmp2, &tmp_head, list) {
      list_del_rcu(&tmp1->list);
      kfree(tmp1);
      // 新策略，quota_list为空，所以没有必要释放quota_list
    }
  }
  
  return len;
}

/*
 * 将策略中的IP地址转化为IP字符串
 */
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

/*
 * 将策略中的端口地址转化为端口字符串
 */
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

/*
 * securityfs中的policy文件的read函数
 */
static ssize_t policy_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
  struct ztlsm_policy *pol;
  char *buf, *buf2;
  ssize_t len=0;
  ssize_t ret;
  char *sip, *dip, *sport, *dport;

  if (*ppos > 0) //只支持从文件起始处开始读
    return 0;

  // 申请缓冲区，全部策略必须能被装入4096字节。
  buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
  if (!buf)
    return -ENOMEM;

  // 小缓冲区，用于承载一条策略的IP和端口
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

  // 将数据搬运到用户态缓冲
  ret = simple_read_from_buffer(user_buf, count, ppos, buf, len);
  kfree(buf);
  kfree(buf2);
  return ret;
}

static const struct file_operations policy_fops = {
  .write = policy_write,
  .read  = policy_read,
};

/*
 * 判断IP地址是否在子网之内
 */
static bool ipv4_prefix_match(__be32 net, u8 mask, __be32 ip)
{
  __be32 mask_be;

  if (mask == 0)
    return true;

  mask_be = cpu_to_be32(~0U << (32 - mask));
  return (net & mask_be) == (ip & mask_be);
}

/*
 * 判断IP地址是否在RFC1918规定的3个保留网段之内
 */
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

/*
 * 判断IP地址是否在主机所在的局域网之内。
 *
 * 这个函数的运行会比较耗费时间，更好的方法是制作缓存，不要每次查询都遍历网络设备。
 */
static bool ipv4_is_local_lan(__be32 ip)
{
  struct net_device *dev;
  struct in_device *in_dev;
  struct in_ifaddr *ifa;

  rcu_read_lock();
  // 遍历主机的所有网络设备
  for_each_netdev(&init_net, dev) {
    in_dev = __in_dev_get_rcu(dev);
    if (!in_dev)
      continue;

    // 遍历网络设备的所有网络地址
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

/*
 * 判断IP地址是否是保留地址。
 */
static inline bool ipv4_is_reserved(__be32 ip)
{
  /* 240.0.0.0/4 */
  return ipv4_prefix_match(cpu_to_be32(0xF0000000), 4, ip);
}

/*
 * 判断IP地址是否是外部地址
 */
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

/*
 * 根据策略中IP地址的类型、掩码和数值，判断输入的IP地址是否匹配。
 */
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

/*
 * 根据策略中端口的类型和数值判断输入的端口是否匹配。
 */
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

/*
 * 判断协议是否匹配
 */
static inline bool proto_match(const struct ztlsm_policy *pol, u8 proto)
{
  return pol->trans_proto == proto;
}

/*
 * 判断策略与五元组的匹配
 */
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

/*
 * 在所有的策略中找到匹配五元组的策略
 */
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

/*
 * 在rcu保护下，找到匹配五元组的策略
 */
static struct ztlsm_policy* get_matched_policy(struct ztlsm_five_tuple *ft)
{
  struct ztlsm_policy *pol;
  rcu_read_lock();
  pol = get_matched_policy_core(ft);
  rcu_read_unlock();
  return pol;
}

/*
 * 从socket和消息头中提取五元组
 */
static int assign_five_tuple(struct socket *sock, struct msghdr *msg, struct ztlsm_five_tuple *ft, int is_recv)
{
  struct sock *sk;
  struct sockaddr_in *sin;
  struct inet_sock *inet;
  
  if (!sock || !sock->sk)
    return 1;

  sk = sock->sk;
  
  /* 现在只支持IPv4 */
  if (sk->sk_family != AF_INET)
    return 1;

  // 从socket中提取协议
  if (sk->sk_protocol == IPPROTO_TCP)
    ft->proto = ZTLSM_TRANSPORT_TCP;
  else if (sk->sk_protocol == IPPROTO_UDP)
    ft->proto = ZTLSM_TRANSPORT_UDP;
  else
    return 1;

  inet = inet_sk(sk);
  if (!msg || !msg->msg_name) {
    /* 对于连接状态的socket（TCP或者连接的UDP），msg_name为空是正常的。
     * 在无法获取msg_name时，从socket中获取所需的数据
     */

    // 在socket中，源总是本地，目的总是远端，但是在策略中不是这样。
    if (is_recv) {
      /* 接收时，远端是源，本地是目的 */
      ft->sip = inet->inet_daddr;
      ft->sport = inet->inet_dport;
      ft->dip = inet->inet_rcv_saddr;
      ft->dport = inet->inet_sport;
    } else {
      /* 发送时，本地是源，远端是目的 */
      ft->sip = inet->inet_rcv_saddr;
      ft->sport = inet->inet_sport;
      ft->dip = inet->inet_daddr;
      ft->dport = inet->inet_dport;
    }
  } else {
    /* 对于无连接的socket，msg_name非空 */
    if (msg->msg_namelen < sizeof(struct sockaddr_in))
      return 1;
    else
      sin = (struct sockaddr_in *)msg->msg_name;

    if (is_recv) {
      /* 接收时，远端是源 */
      ft->sip   = sin->sin_addr.s_addr;
      ft->sport = sin->sin_port;
    
      /* 本地是目的 */
      ft->dip   = inet->inet_rcv_saddr;
      ft->dport = inet->inet_sport;
    } else {
      /* 发送时，本地是源 */
      ft->sip   = inet->inet_rcv_saddr;
      ft->sport = inet->inet_sport;
  
      /* 远端是目的 */
      ft->dip   = sin->sin_addr.s_addr;
      ft->dport = sin->sin_port;
    }
  }

  return 0;
}

/*
 * 检查策略是否允许size大小的网络包
 */
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

  // 获取当前时间
  now = ktime_get();

  // 获取策略的流量锁
  spin_lock(&pol->quota_lock);

  // 从尾部开始遍历，尾部是距离现在最远的包
  list_for_each_entry_safe_reverse(entry, tmp, &pol->quota_list, list) {
    // 计算时间差值
    delta_ns = ktime_to_ns(ktime_sub(now, entry->ts));

    // 如果已经进入时间窗口，那么在此之前的更接近头部的包也都在时间窗口之内
    if (delta_ns <= window_ns)
      break;

    // 不在时间窗口之内，删除当前包，在缓存的流量大小中减去当前包的大小
    list_del(&entry->list);
    pol->cached_size -= entry->size;
    kfree(entry);
  }

  // 判断在加上当前包的大小后，是否超过了策略规定的限额
  total = pol->cached_size + size;
  if (total > pol->quota) {
    ret = -EACCES;
    goto out;
  }

  // 没有超限额，记录新增加的包。
  entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
  if (!entry) {
    // 申请不到内存，先放行
    ret = 0;
    goto out;
  }

  entry->ts = now;
  entry->size = size;

  // 将新包加入策略的流量链表
  list_add(&entry->list, &pol->quota_list);

  // 增加缓存的流量大小值
  pol->cached_size += size;

  ret = 0;
 out:
  spin_unlock(&pol->quota_lock);
  return ret;
}

/*
 * 查找五元组符合的策略，再将网络包大小加入策略的流量链表
 */
static int match_and_check(struct ztlsm_five_tuple *ft, int size)
{
  struct ztlsm_policy *pol;
  int ret;
  
  rcu_read_lock();
  /* 查找策略 */
  pol = get_matched_policy_core(ft);
  if (!pol) {
    rcu_read_unlock();
    return -EACCES;
  }
  /* 检查策略的限额 */
  ret = check_quota(pol, size);
  rcu_read_unlock();

  return ret;
}

/*
 * LSM的connect钩子函数
 */
static int ztlsm_socket_connect(struct socket *sock, struct sockaddr *addr, int addrlen)
{
  struct sock *sk;
  struct ztlsm_policy *pol;
  struct sockaddr_in *sin;
  struct ztlsm_five_tuple ft;

  // 安全检查
  if (!sock || !addr)
    return 0;

  sk = sock->sk;
  
  /* 现在只支持IPv4 */
  if (!sk || sk->sk_family != AF_INET)
    return 0;

  if (sk->sk_protocol == IPPROTO_TCP)
    ft.proto = ZTLSM_TRANSPORT_TCP;
  else if (sk->sk_protocol == IPPROTO_UDP)
    ft.proto = ZTLSM_TRANSPORT_UDP;
  else
    return 0;

  /* 本地是源 */
  ft.sip   = inet_sk(sk)->inet_saddr;
  ft.sport = inet_sk(sk)->inet_sport;

  if (ft.sip == 0) {
    // 本地地址还没有绑定，先允许操作，后面在收发消息的钩子函数会进行判断
    return 0;
  }
  
  /* 远端是目的 */
  sin = (struct sockaddr_in *)addr;
  ft.dip   = sin->sin_addr.s_addr;
  ft.dport = sin->sin_port;

  pol = get_matched_policy(&ft);
  if (pol) {
    /* 本模块采用白名单，有策略意味着允许 */
    return 0;
  } else {
    printk(KERN_WARNING "ZT LSM: connection denied\n");
    return -EACCES;
  }
}

/*
 * LSM的accept钩子函数
 */
static int ztlsm_socket_accept(struct socket *sock, struct socket *newsock)
{
  struct sock *sk;
  struct ztlsm_policy *pol;
  struct ztlsm_five_tuple ft;

  // 安全检查
  if (!newsock)
    return 0;

  sk = newsock->sk;
  
  /* 现在只支持 IPv4 */
  if (!sk || sk->sk_family != AF_INET)
    return 0;

  // 获取协议
  if (sk->sk_protocol == IPPROTO_TCP)
    ft.proto = ZTLSM_TRANSPORT_TCP;
  else if (sk->sk_protocol == IPPROTO_UDP)
    ft.proto = ZTLSM_TRANSPORT_UDP;
  else
    return 0;
      
  /* 远端是源 */
  ft.sip   = inet_sk(sk)->inet_daddr;
  ft.sport = inet_sk(sk)->inet_dport;

  /* 本地端是目的 */
  ft.dip   = inet_sk(sk)->inet_rcv_saddr;
  ft.dport = inet_sk(sk)->inet_sport;

  pol = get_matched_policy(&ft);
  if (pol) {
    // 本LSM采用白名单，有策略意味着允许
    return 0;
  } else {
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
    // 无法构建五元组，允许操作进行。
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
    // 无法构建五元组，允许操作进行
    return 0;
  
  return match_and_check(&ft, size);
}

static int __init ztlsm_files_init(void)
{
  int ret;
  static struct dentry *ztlsm_dir;
  static struct dentry *policy_file;
  
  printk(KERN_INFO "ZT LSM: files init.\n");

  // 创建 securityfs 目录： /sys/kernel/security/ztlsm
  ztlsm_dir = securityfs_create_dir("ztlsm", NULL);
  if (IS_ERR(ztlsm_dir)) {
    ret = PTR_ERR(ztlsm_dir);
    printk(KERN_ERR "ZT LSM: Failed to create ztlsm dir. The error is %d.\n", ret);
    return ret;
  }

  // 创建 securityfs 文件： /sys/kernel/security/ztlsm/policy
  policy_file = securityfs_create_file("policy", 0644, ztlsm_dir, NULL, &policy_fops);
  if (IS_ERR(policy_file)) {
    ret = PTR_ERR(policy_file);
    printk(KERN_ERR "ZT LSM: Failed to create policy file. The error is %d.\n", ret);
    securityfs_remove(ztlsm_dir);
    return ret;
  }

  return 0;
}

/*
 * 添加两条缺省的策略，允许任何网络连接和网络收发。
 */
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

  ret = policy_add(&pol, &ztlsm_ipv4_policy_list);
  if (ret) return ret;

  pol.trans_proto = ZTLSM_TRANSPORT_UDP;

  ret = policy_add(&pol, &ztlsm_ipv4_policy_list);
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

  // 注册钩子函数
  security_add_hooks(ztlsm_hooks,
		     ARRAY_SIZE(ztlsm_hooks),
		     &ztlsm_id);

  // 创建 securityfs 中的目录和文件
  ret = ztlsm_files_init();
  if (ret) return ret;

  // 添加缺省策略
  ret = policy_add_default_allow();
  if (ret) return ret;

  return 0;
}

DEFINE_LSM(ztlsm) = {
  .name = "ztlsm",
  .init = ztlsm_init,
};
