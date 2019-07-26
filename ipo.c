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

#include <net/icmp.h>
#include <net/ip_tunnels.h>
#include <net/rtnetlink.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <net/protocol.h>
#include <net/ip_fib.h>
#include <net/ip.h>
#include <net/gro_cells.h>

// ip option header
struct opthdr {
	uint8_t type;
	uint8_t len;
};

struct optdata {
	char src;
	char dst;
};

struct ipo_dev {
	struct gro_cells	gro_cells;
	struct net_device	*dev;
};

struct ipo_net {
	struct ipo_dev* ipo_dev;
};

static int ipo_net_id;

static int __net_init ipo_init_net(struct net *net)
{
	return 0;
}

static void __net_exit ipo_exit_net(struct net *net)
{
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

	static inline struct rtable *ip_route_output_ipo(struct net *net,
													struct flowi4 *fl4,
													int proto,
													__be32 daddr, __be32 saddr,
													__be32 key, __u8 tos, int oif)
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

static void ipo_get_stats64(struct net_device *dev,
												   struct rtnl_link_stats64 *stats)
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
	nh = (struct iphdr *)skb_network_header(skb);
	pr_debug("IPO ipo_rx head %p, tail %d, "
				  "data %p, end %d, len %u, headroom %d, "
	  "mac %d, network %d, transport %d, ip payload len %d\n",
		   skb->head, skb->tail,
		   skb->data, skb->end, skb->len, skb_headroom(skb),
		   skb->mac_header, skb->network_header, skb->transport_header, ntohs(nh->tot_len));
	pr_debug("IPO ipo_rx dev %s saddr %pI4, daddr %pI4, skb->protocol %d, skb->pkt_type %d, nh->protocol %d, tos %d, ip_summed %d, nh->version %d, ntohs(nh->tot_len)=%d, nh->ihl*4=%d, nh->ttl=%d\n", dev->name, &nh->saddr, &nh->daddr, skb->protocol, skb->pkt_type, nh->protocol, nh->tos, skb->ip_summed, nh->version, ntohs(nh->tot_len), nh->ihl*4, nh->ttl);
	// TODO search source ip prefix from route such as 192.168.1.0/24 via 10.0.0.2 dev ipo0 onlink
	optdata = (struct optdata *)(skb_network_header(skb) + sizeof(struct iphdr) + sizeof(struct opthdr));
	pchar = (char*)&nh->saddr;
	if (nh->saddr == in_aton("10.0.0.2")) {
		pchar[0] = 192;
		pchar[1] = 168;
		pchar[2] = 1;

	} else if (nh->saddr == in_aton("10.0.0.3")) {
		pchar[0] = 192;
		pchar[1] = 168;
		pchar[2] = 2;
	}
	for_primary_ifa(ipo->dev->ip_ptr) {
		nh->daddr = ifa->ifa_local;
			break;
	} endfor_ifa(ipo->dev);
	pchar[3] = optdata->src;
	pchar[7] = optdata->dst;

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
	printk(KERN_WARNING "IPO ipo_err\n");
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

static int ipo_dev_init(struct net_device *dev)
{
	struct ipo_dev *ipo = netdev_priv(dev);
	int err;
	printk(KERN_INFO "IPO ipo_dev_init %s", dev->name);
	ipo->dev = dev;
	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;
	// preserve headroom for option fields.
	// It seems needed_headroom multiples by 4
	dev->needed_headroom = overhead;
	err = gro_cells_init(&ipo->gro_cells, dev);
	if (err) {
		free_percpu(dev->tstats);
		return err;
	}
	return 0;
}

static void ipo_dev_uninit(struct net_device *dev)
{
	struct ipo_dev *ipo = netdev_priv(dev);
	gro_cells_destroy(&ipo->gro_cells);
	free_percpu(dev->tstats);
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
