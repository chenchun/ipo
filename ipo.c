#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/slab.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/u64_stats_sync.h>
#include <linux/etherdevice.h>
#include <linux/percpu-defs.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/if_tunnel.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/kthread.h>

#include <net/icmp.h>
#include <net/ip_tunnels.h>
#include <net/rtnetlink.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <net/protocol.h>
#include <net/ip_fib.h>
#include <net/ip.h>
#include <net/gro_cells.h>

// TODO multiple ipo devices ?

// ip option header
struct opthdr {
	uint8_t type;
	uint8_t len;
};

struct optdata {
	char src;
	char dst;
};

#define ROUTE_HASH_BITS	12
#define ROUTE_HASH_SIZE	(1<<ROUTE_HASH_BITS)

struct ipo_dev {
	struct gro_cells	gro_cells;
	struct net_device	*dev;
	struct hlist_head	route_head[ROUTE_HASH_SIZE];
	spinlock_t	  hash_lock;
};

struct ipo_net {
	struct ipo_dev* ipo_dev;
	struct sock *sk;	/* ROUTE raw socket */
	struct task_struct *route_task;
	unsigned char *recvbuf;
};

struct ipo_route {
	struct hlist_node hlist;	/* linked list of entries */
	struct rcu_head	  rcu;
	__be32 gateway;
	__be32 dst;
};

/* Hash chain to use given gateway address */
static inline struct hlist_head *ipo_route_head(struct ipo_dev *ipo, __be32 gateway)
{
	return &ipo->route_head[hash_32(gateway, ROUTE_HASH_BITS)];
}

static struct ipo_route *ipo_find_route(struct ipo_dev *ipo,  const __be32 gateway)
{
	struct hlist_head *head = ipo_route_head(ipo, gateway);
	struct ipo_route *f;

	hlist_for_each_entry_rcu(f, head, hlist) {
		if (gateway == f->gateway)
			return f;
	}
	return NULL;
}

/* Add new entry to route table -- assumes lock held */
static int ipo_route_add(struct ipo_dev *ipo, const __be32 gateway, __be32 dst)
{
	struct ipo_route *f;
	f = ipo_find_route(ipo, gateway);
	if (f) {
		return -EEXIST;
	}
	f = kmalloc(sizeof(*f), GFP_ATOMIC);
	if (!f)
		return -ENOMEM;
	f->dst = dst;
	f->gateway = gateway;
	hlist_add_head_rcu(&f->hlist, ipo_route_head(ipo, gateway));
	pr_info("IPO add route gateway: %pI4, dst %pI4\n", &gateway, &dst);
}

static void ipo_route_free(struct rcu_head *head)
{
	struct ipo_route *f = container_of(head, struct ipo_route, rcu);
	kfree(f);
}

static void ipo_route_destroy(struct ipo_dev *ipo, struct ipo_route *f)
{
	pr_info("IPO delete route %pI4\n", &f->gateway);
	hlist_del_rcu(&f->hlist);
	call_rcu(&f->rcu, ipo_route_free);
}

static int ipo_route_delete(struct ipo_dev *ipo, __be32 gateway)
{
	struct ipo_route *f;
	int err = -ENOENT;
	spin_lock_bh(&ipo->hash_lock);
	f = ipo_find_route(ipo, gateway);
	if (f) {
		ipo_route_destroy(ipo, f);
		err = 0;
	}
	spin_unlock_bh(&ipo->hash_lock);
	return err;
}

static int ipo_net_id;

static int recvbuf_size = 65536;

const struct nla_policy rtm_ipv4_policy[RTA_MAX + 1] = {
	[RTA_DST]		= { .type = NLA_U32 },
	[RTA_SRC]		= { .type = NLA_U32 },
	[RTA_IIF]		= { .type = NLA_U32 },
	[RTA_OIF]		= { .type = NLA_U32 },
	[RTA_GATEWAY]		= { .type = NLA_U32 },
	[RTA_PRIORITY]		= { .type = NLA_U32 },
	[RTA_PREFSRC]		= { .type = NLA_U32 },
	[RTA_METRICS]		= { .type = NLA_NESTED },
	[RTA_MULTIPATH]		= { .len = sizeof(struct rtnexthop) },
	[RTA_FLOW]		= { .type = NLA_U32 },
};

static int rtm_to_fib_config(struct nlmsghdr *nlh, struct fib_config *cfg)
{
	struct nlattr *attr;
	int err, remaining;
	struct rtmsg *rtm;

	err = nlmsg_validate(nlh, sizeof(*rtm), RTA_MAX, rtm_ipv4_policy);
	if (err < 0)
		goto errout;

	memset(cfg, 0, sizeof(*cfg));

	rtm = nlmsg_data(nlh);
	cfg->fc_dst_len = rtm->rtm_dst_len;
	cfg->fc_tos = rtm->rtm_tos;
	cfg->fc_table = rtm->rtm_table;
	cfg->fc_protocol = rtm->rtm_protocol;
	cfg->fc_scope = rtm->rtm_scope;
	cfg->fc_type = rtm->rtm_type;
	cfg->fc_flags = rtm->rtm_flags;
	cfg->fc_nlflags = nlh->nlmsg_flags;
	cfg->fc_nlinfo.nlh = nlh;
	if (cfg->fc_type > RTN_MAX) {
		err = -EINVAL;
		goto errout;
	}

	nlmsg_for_each_attr(attr, nlh, sizeof(struct rtmsg), remaining) {
		switch (nla_type(attr)) {
			case RTA_DST:
				cfg->fc_dst = nla_get_be32(attr);
				break;
			case RTA_OIF:
				cfg->fc_oif = nla_get_u32(attr);
				break;
			case RTA_GATEWAY:
				cfg->fc_gw = nla_get_be32(attr);
				break;
			case RTA_PRIORITY:
				cfg->fc_priority = nla_get_u32(attr);
				break;
			case RTA_PREFSRC:
				cfg->fc_prefsrc = nla_get_be32(attr);
				break;
			case RTA_METRICS:
				cfg->fc_mx = nla_data(attr);
				cfg->fc_mx_len = nla_len(attr);
				break;
			case RTA_MULTIPATH:
				cfg->fc_mp = nla_data(attr);
				cfg->fc_mp_len = nla_len(attr);
				break;
			case RTA_FLOW:
				cfg->fc_flow = nla_get_u32(attr);
				break;
			case RTA_TABLE:
				cfg->fc_table = nla_get_u32(attr);
				break;
		}
	}

	return 0;
	errout:
	return err;
}

int route_thread(void *data) {
	struct ipo_net *ipon = (struct ipo_net *)data;
	struct msghdr msg;
	struct kvec iov;
	int recvlen = 0;
	struct nlmsghdr *nh;
	struct fib_config cfg;
	pr_info("IPO start route_thread\n");
	while (!kthread_should_stop()) {
		ipon->sk->sk_allocation = GFP_NOIO | __GFP_MEMALLOC;
		iov.iov_base = ipon->recvbuf;
		iov.iov_len = recvbuf_size;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = MSG_NOSIGNAL;
		recvlen = kernel_recvmsg(ipon->sk->sk_socket, &msg, &iov, 1, recvbuf_size, msg.msg_flags);
		if (recvlen > 0) {
			for (nh = (struct nlmsghdr *) ipon->recvbuf; NLMSG_OK (nh, recvlen);
				 nh = NLMSG_NEXT (nh, recvlen)) {
				if (nh->nlmsg_type == NLMSG_DONE)
					break;
				if (nh->nlmsg_type == NLMSG_ERROR) {
					pr_warn("IPO receive error nlmsg");
				}
				rtm_to_fib_config(nh, &cfg);
				if (nh->nlmsg_type == RTM_NEWROUTE) {
					if (cfg.fc_gw == 0)
						continue;
					spin_lock_bh(&ipon->ipo_dev->hash_lock);
					ipo_route_add(ipon->ipo_dev, cfg.fc_gw, cfg.fc_dst);
					spin_unlock_bh(&ipon->ipo_dev->hash_lock);
				} else if (nh->nlmsg_type == RTM_DELROUTE) {
					ipo_route_delete(ipon->ipo_dev, cfg.fc_gw);
				}
			}
		} else {
			schedule_timeout(msecs_to_jiffies(1000));
		}
	}
	return 0;
}

static void __net_exit ipo_exit_net(struct net *net)
{
	pr_debug("IPO ipo_exit_net");
}

static int __net_init ipo_init_net(struct net *net)
{
	pr_debug("IPO ipo_init_net");
	return 0;
}

static struct pernet_operations ipo_net_ops = {
	.init = ipo_init_net,
	.exit = ipo_exit_net,
	.id   = &ipo_net_id,
	.size = sizeof(struct ipo_net),
};

const unsigned short overhead = sizeof(struct opthdr) + sizeof(struct optdata);

#if defined(DEBUG)
void printiphdr(const char *pre, char *p, uint32_t len) {
	uint32_t i;
	if (len > 100) {
		len = 100;
	}
	printk(KERN_INFO);
	printk(pre);
	for (i = 0; i < len; i++) {
		if (i == 12 || i == 20) {
			printk("  ");
		}
		printk("%02hhx ", *p);
		p++;
	}
	printk("\n");
}
#else
void printiphdr(const char *pre, char *p, uint32_t len) {}
#endif

static inline struct rtable *ip_route_output_ipo(struct net *net, struct flowi4 *fl4,
		int proto, __be32 daddr, __be32 saddr, __be32 key, __u8 tos, int oif)
{
	memset(fl4, 0, sizeof(*fl4));
	fl4->flowi4_oif = oif;
	fl4->daddr = daddr;
	fl4->saddr = saddr;
	fl4->flowi4_tos = tos;
	fl4->flowi4_proto = proto;
	fl4->fl4_gre_key = key;
	return ip_route_output_key(net, fl4);
}

static void ipo_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	int i;

	for_each_possible_cpu(i) {
		const struct pcpu_sw_netstats *tstats;
		u64 tbytes, tpackets, rbytes, rpackets;
		unsigned int start;

		tstats = per_cpu_ptr(dev->tstats, i);
		do {
			start = u64_stats_fetch_begin_irq(&tstats->syncp);
			tbytes = tstats->tx_bytes;
			tpackets = tstats->tx_packets;
			rbytes = tstats->rx_bytes;
			rpackets = tstats->rx_packets;
		} while (u64_stats_fetch_retry_irq(&tstats->syncp, start));
		stats->tx_bytes += tbytes;
		stats->tx_packets += tpackets;
		stats->rx_bytes += rbytes;
		stats->rx_packets += rpackets;
	}
}

struct fib_table *ipo_fib_get_table(struct net *net, u32 id)
{
	struct fib_table *tb;
	struct hlist_head *head;
	unsigned int h;

	if (id == 0)
		id = RT_TABLE_MAIN;
	h = id & (FIB_TABLE_HASHSZ - 1);

	rcu_read_lock();
	head = &net->ipv4.fib_table_hash[h];
	hlist_for_each_entry_rcu(tb, head, tb_hlist) {
		if (tb->tb_id == id) {
			rcu_read_unlock();
			return tb;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static inline int fib_lookup_by_gateway(struct net *net, const struct flowi4 *flp,
							 struct fib_result *res)
{
	struct fib_table *table;
	int ret;
	table = ipo_fib_get_table(net, RT_TABLE_MAIN);
	ret = fib_table_lookup(table, flp, res, FIB_LOOKUP_NOREF);
	if (!ret)
		return 0;
	return -ret;
}

const int IPPROTO_IPO_ADDITION = 143;

// Check include/linux/netdevice.h for enum rx_handler_result
static int ipo_rx(struct sk_buff *skb)
{
	struct iphdr *nh;
	struct optdata *optdata;
	int err;
	char *pchar;
	struct net_device *dev = skb->dev;
	struct pcpu_sw_netstats *tstats;
	struct net *net = dev_net(dev);
	struct ipo_dev *ipo = ((struct ipo_net *) net_generic(net, ipo_net_id))->ipo_dev;
	struct ipo_route *route;
	nh = (struct iphdr *)skb_network_header(skb);
	pr_debug("IPO ipo_rx head %p, tail %d, "
				  "data %p, end %d, len %u, headroom %d, "
	  "mac %d, network %d, transport %d, ip payload len %d\n",
		   skb->head, skb->tail,
		   skb->data, skb->end, skb->len, skb_headroom(skb),
		   skb->mac_header, skb->network_header, skb->transport_header, ntohs(nh->tot_len));
	pr_debug("IPO ipo_rx dev %s saddr %pI4, daddr %pI4, skb->protocol %d, skb->pkt_type %d, nh->protocol %d, tos %d, ip_summed %d, nh->version %d, ntohs(nh->tot_len)=%d, nh->ihl*4=%d, nh->ttl=%d\n", dev->name, &nh->saddr, &nh->daddr, skb->protocol, skb->pkt_type, nh->protocol, nh->tos, skb->ip_summed, nh->version, ntohs(nh->tot_len), nh->ihl*4, nh->ttl);
	// search source ip prefix from route such as 192.168.1.0/24 via 10.0.0.2 dev ipo0 onlink
	optdata = (struct optdata *)(skb_network_header(skb) + sizeof(struct iphdr) + sizeof(struct opthdr));
	route = ipo_find_route(ipo, nh->saddr);
	if (route == NULL) {
		pr_warn("IPO ipo_rx route not found for %pI4\n", &nh->saddr);
		goto drop;
	}
	pr_debug("IPO ipo_rx find route for %pI4, dst %pI4\n", &nh->saddr, &route->dst);
	nh->saddr = route->dst;
	// get dst ip prefix from ipo dev ip
	for_primary_ifa(ipo->dev->ip_ptr) {
		nh->daddr = ifa->ifa_local;
		break;
	} endfor_ifa(ipo->dev);
	pchar = (char*)&nh->saddr;
	pchar[3] = optdata->src;
	pchar[7] = optdata->dst;

	// move IP header behind
	memmove(skb_network_header(skb) + overhead, skb_network_header(skb), sizeof(struct iphdr));
	skb_set_network_header(skb, skb_network_offset(skb)+overhead);
	nh = (struct iphdr *)skb_network_header(skb);
	nh->ihl -= overhead/4;
	nh->tot_len = htons(ntohs(nh->tot_len) - overhead);
	nh->protocol -= IPPROTO_IPO_ADDITION;
	ip_send_check(nh);
	// push back IP hdr
	skb_push(skb, sizeof(struct iphdr));

	tstats = this_cpu_ptr(ipo->dev->tstats);
	u64_stats_update_begin(&tstats->syncp);
	tstats->rx_packets++;
	tstats->rx_bytes += skb->len;
	u64_stats_update_end(&tstats->syncp);

	printiphdr("IPO ipo_rx decode: ", (char *) skb_network_header(skb), ntohs(nh->tot_len));
	skb->dev = ipo->dev; //TODO what does this do?
	skb_scrub_packet(skb, true);

	pr_debug("IPO ipo_rx gro_cells_receive skb->protocol %d\n", skb->protocol);
	pr_debug("IPO ipo_rx s %pI4, d %pI4, proto %d, ver %d, tl %d, ihl*4 %d, ttl=%d\n", &nh->saddr, &nh->daddr, nh->protocol, nh->version, ntohs(nh->tot_len), nh->ihl*4, nh->ttl);
	err = gro_cells_receive(&ipo->gro_cells, skb);
	if (err != 0) {
		printk(KERN_WARNING "IPO gro_cells_receive fail\n");
		goto drop;
	}
	return 0;
drop:
	printk(KERN_WARNING "IPO rx_error\n");
	kfree_skb(skb);
	return 0;
}

static void ipo_err(struct sk_buff *skb, u32 info) {
	pr_warn("IPO ipo_err %d\n", info);
}

static const struct net_protocol net_ipo_protocol = {
	.handler     = ipo_rx,
	.err_handler = ipo_err,
	.netns_ok    = 1,
	.no_policy = 1,
};

static inline void iptunnel_xmit_ipo(struct sk_buff *skb, struct net_device *dev)
{
	int err;
	int pkt_len = skb->len - skb_transport_offset(skb);
	struct pcpu_sw_netstats *tstats = this_cpu_ptr(dev->tstats);

	nf_reset(skb);

	err = ip_local_out(skb);
	if (likely(net_xmit_eval(err) == 0)) {
		u64_stats_update_begin(&tstats->syncp);
		tstats->tx_bytes += pkt_len;
		tstats->tx_packets++;
		u64_stats_update_end(&tstats->syncp);
	} else {
		dev->stats.tx_errors++;
		dev->stats.tx_aborted_errors++;
	}
}

static netdev_tx_t ipo_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct iphdr *nh;
	char *charp;
	struct opthdr *opthdr;
	struct optdata *optdata;
	struct flowi4 fl4;
	struct rtable *rt;
	__be32 dst;
	int mtu;
	nh = (struct iphdr *)skb_network_header(skb);
	if (ntohs(eth_hdr(skb)->h_proto) != ETH_P_IP) {
		printk(KERN_WARNING "Proto not ETH_P_IP");
		goto tx_error;
	}
	if (unlikely(skb_headroom(skb) < overhead)) {
		printk(KERN_WARNING "IPO headroom %d too small\n", skb_headroom(skb));
		goto tx_error;
	}
	if (nh->ihl == 5) {
		rt = skb_rtable(skb);
		if (rt == NULL) {
			printk(KERN_WARNING "IPO skb_rtable is null\n");
			goto tx_error;
		}
		pr_debug("IPO rt.dst %pI4\n", &rt->rt_gateway);
		dst = rt->rt_gateway;
		printiphdr("IPO ipo_xmit original: ", skb_network_header(skb), ntohs(nh->tot_len));
		pr_debug("IPO ipo_xmit head %p, tail %d, "
			   "data %p, end %d, len %u, headroom %d, "
			   "mac %d, network %d, transport %d, ip payload len %d\n",
			   skb->head, skb->tail,
			   skb->data, skb->end, skb->len, skb_headroom(skb),
			   skb->mac_header, skb->network_header, skb->transport_header, ntohs(nh->tot_len));
		if (skb_mac_header_was_set(skb)) {
#ifdef NET_SKBUFF_DATA_USES_OFFSET
			skb->mac_header = ~0;
#else
			skb->mac_header = NULL;
#endif
			skb_pull(skb, sizeof(struct ethhdr));
		}
		memcpy(skb_network_header(skb) - overhead, skb_network_header(skb), sizeof(struct iphdr));
		skb_set_network_header(skb, skb_network_offset(skb)-overhead);
		skb_push(skb, overhead);
		// copy ip headers ahead
		nh = (struct iphdr *)skb_network_header(skb);
		nh->ihl += overhead/4;
		nh->tot_len = htons(ntohs(nh->tot_len) + overhead);
		nh->protocol += IPPROTO_IPO_ADDITION;

		charp = skb_network_header(skb);
		opthdr = (struct opthdr *)(charp + sizeof(struct iphdr));
		opthdr->type = 40;
		opthdr->len = overhead;
		optdata = (struct optdata *)((char *)opthdr + sizeof(struct opthdr));
		printiphdr("IPO ipo_xmit int: ", skb_network_header(skb), ntohs(nh->tot_len));
		// save last byte of src ip to opt src
		optdata->src = charp[15];
		optdata->dst = charp[19];
		nh->daddr = dst;
		//TODO checksum ?
		rt = ip_route_output_ipo(dev_net(dev), &fl4,
									nh->protocol,
									nh->daddr, 0,
									TUNNEL_NO_KEY,
									RT_TOS(nh->tos), 0);
		if (IS_ERR(rt)) {
			dev->stats.tx_carrier_errors++;
			printk(KERN_INFO "IPO route lookup error\n");
			goto tx_error;
		}
		if (rt->dst.dev == dev) {
			printk(KERN_WARNING "IPO circular route to %d\n", nh->daddr);
			ip_rt_put(rt);
			dev->stats.collisions++;
			goto tx_error;
		}

		mtu = skb_dst(skb)? dst_mtu(skb_dst(skb)) : dev->mtu;
		if (skb_dst(skb))
			skb_dst(skb)->ops->update_pmtu(skb_dst(skb), NULL, skb, mtu);

		if (!skb_is_gso(skb) &&
			(nh->frag_off&htons(IP_DF)) &&
			mtu < ntohs(nh->tot_len)) {
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
			ip_rt_put(rt);
			goto tx_error;
		}

		nh->saddr = inet_select_addr(rt->dst.dev, rt_nexthop(rt, nh->daddr), RT_SCOPE_UNIVERSE);
		pr_debug("IPO rt.rt_gateway %pI4 dev %s, saddr %pI4\n", &rt->rt_gateway, rt->dst.dev->name, &nh->saddr);
//		nh->saddr = rt->rt_gateway;
		skb_dst_drop(skb);
		skb_dst_set(skb, &rt->dst);
		printiphdr("IPO ipo_xmit new: ", skb_network_header(skb), ntohs(nh->tot_len));
		pr_debug("IPO ipo_xmit head %p, tail %d, data %p, end %d, len %d, headroom %d, mac %d, network %d, transport %d, ip payload len %d, skb->protocol %d\n", skb->head, skb->tail, skb->data, skb->len, skb->end, skb_headroom(skb), skb->mac_header, skb->network_header, skb->transport_header, ntohs(nh->tot_len), skb->protocol);
		iptunnel_xmit_ipo(skb, dev);
	} else {
		// TODO
	}
	pr_debug(KERN_INFO "IPO tx_ok\n");
	return NETDEV_TX_OK;
tx_error:
	printk(KERN_WARNING "IPO tx_error\n");
	dev->stats.tx_errors++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int ipo_newlink(struct net *net, struct net_device *dev,
					   struct nlattr *tb[], struct nlattr *data[])
{
	int err;
	struct ipo_net *ipon = net_generic(net, ipo_net_id);
	struct ipo_dev *ipo = netdev_priv(dev);
	printk(KERN_INFO "IPO ipo_newlink %s", dev->name);
	err = register_netdevice(dev);
	if (err) {
		return err;
	}
	ipon->ipo_dev = ipo;
	return 0;
}

static void ipo_dev_uninit(struct net_device *dev)
{
	struct ipo_dev *ipo = netdev_priv(dev);
	struct ipo_net *ipon = net_generic(dev_net(dev), ipo_net_id);
	pr_info("IPO ipo_dev_uninit %s", dev->name);
	if (ipon->route_task) {
		kthread_stop(ipon->route_task);
		ipon->route_task = NULL;
	}
	sk_release_kernel(ipon->sk);
	ipon->sk = NULL;
	if (ipon->recvbuf) {
		kfree(ipon->recvbuf);
	}
	gro_cells_destroy(&ipo->gro_cells);
	free_percpu(dev->tstats);
}

static int ipo_dev_init(struct net_device *dev)
{
	struct ipo_dev *ipo = netdev_priv(dev);
	struct ipo_net *ipon = net_generic(dev_net(dev), ipo_net_id);
	int rc;
	struct socket *sock;
	struct sockaddr_nl nl_route_addr = {
		.nl_family = AF_NETLINK,
	};
	pr_info("IPO ipo_dev_init %s", dev->name);
	nl_route_addr.nl_groups |= (1 << (RTNLGRP_IPV4_ROUTE - 1));
	ipo->dev = dev;
	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;
	// preserve headroom for option fields.
	// It seems needed_headroom multiples by 4
	dev->needed_headroom = overhead;
	rc = gro_cells_init(&ipo->gro_cells, dev);
	if (rc) {
		goto fail;
	}
	ipon->recvbuf = kmalloc(recvbuf_size, GFP_KERNEL);
	if (!ipon->recvbuf) {
		pr_err("%s: Failed to alloc recvbuf.\n", __func__);
		rc = -1;
		goto fail;
	}

	rc = sock_create_kern(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE, &sock);
	if (rc < 0) {
		pr_err("NETLINK_ROUTE sock create failed, rc %d\n", rc);
		goto fail;
	}
	sk_change_net(sock->sk, dev_net(dev));
	ipon->sk = sock->sk;
	rc = kernel_bind(sock, (struct sockaddr *) &nl_route_addr,
					 sizeof(nl_route_addr));
	if (rc < 0) {
		pr_err("bind for NETLINK_ROUTE sock %d\n", rc);
		goto fail;
	}
	inet_sk(sock->sk)->mc_loop = 0;

	ipon->route_task = kthread_create(route_thread, ipon, "ipo_route_task");
	if(IS_ERR(ipon->route_task)){
		pr_err("Unable to start route kernel thread.\n");
		rc = PTR_ERR(ipon->route_task);
		ipon->route_task = NULL;
		goto fail;
	}
	pr_info("created ipo k thread %d\n", ipon->route_task->pid);
	wake_up_process(ipon->route_task);
	return rc;
fail:
	ipo_dev_uninit(dev);
	return rc;
}

static int ipo_change_carrier(struct net_device *dev, bool new_carrier)
{
	if (new_carrier)
		netif_carrier_on(dev);
	else
		netif_carrier_off(dev);
	return 0;
}

static const struct net_device_ops ipo_netdev_ops = {
	.ndo_init		= ipo_dev_init,
	.ndo_uninit		= ipo_dev_uninit,
	.ndo_start_xmit		= ipo_xmit,
	.ndo_get_stats64	= ipo_get_stats64,
	.ndo_change_carrier	= ipo_change_carrier,
};

#define IPO_FEATURES (NETIF_F_SG |		\
		       NETIF_F_FRAGLIST |	\
		       NETIF_F_HIGHDMA |	\
		       NETIF_F_HW_CSUM |	\
			   NETIF_F_RXCSUM)

static void ipo_setup(struct net_device *dev)
{
	unsigned h;
	struct ipo_dev *ipo = netdev_priv(dev);
	ether_setup(dev);
	dev->netdev_ops		= &ipo_netdev_ops;

	dev->type		= ARPHRD_TUNNEL;
	dev->flags		= IFF_NOARP;
	dev->iflink		= 0;
	dev->addr_len		= 4;
	dev->features		|= NETIF_F_LLTX;
	netif_keep_dst(dev);

	dev->features		|= IPO_FEATURES;
	dev->hw_features	|= IPO_FEATURES;
	eth_hw_addr_random(dev);
	spin_lock_init(&ipo->hash_lock);
	for (h = 0; h < ROUTE_HASH_SIZE; ++h)
		INIT_HLIST_HEAD(&ipo->route_head[h]);
}

static int ipo_validate(struct nlattr *tb[], struct nlattr *data[])
{
	printk(KERN_INFO "IPO ipo_validate");
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	return 0;
}

static struct rtnl_link_ops ipo_link_ops __read_mostly = {
	.kind		= "ipo",
	.setup		= ipo_setup,
	.validate	= ipo_validate,
	.newlink	= ipo_newlink,
	.priv_size	= sizeof(struct ipo_dev),
};

int supportedProtocol[3] = {IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};

static int __init ipo_init_module(void)
{
	int err = 0;
	int i = 0;
	for (; i < sizeof(supportedProtocol)/sizeof(int); i++) {
		if (inet_add_protocol(&net_ipo_protocol, IPPROTO_IPO_ADDITION + supportedProtocol[i]) < 0) {
			pr_err("can't add protocol\n");
			return -EAGAIN;
		}
	}
	err = register_pernet_device(&ipo_net_ops);
	if (err < 0)
		return err;
	rtnl_lock();
	err = __rtnl_link_register(&ipo_link_ops);
	rtnl_unlock();
	if (err < 0) {
		unregister_pernet_device(&ipo_net_ops);
	}
	printk(KERN_INFO "IPO installed overhead %d\n", overhead);
	return err;
}

static void __exit ipo_cleanup_module(void)
{
	int i = 0;
	rtnl_link_unregister(&ipo_link_ops);
	for (; i < sizeof(supportedProtocol)/sizeof(int); i++) {
		inet_del_protocol(&net_ipo_protocol, IPPROTO_IPO_ADDITION + supportedProtocol[i]);
	}
	unregister_pernet_device(&ipo_net_ops);
	printk(KERN_INFO "IPO uninstalled\n");
}

module_init(ipo_init_module);
module_exit(ipo_cleanup_module);
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK("ipo");
