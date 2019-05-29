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
#include<linux/inet.h>
#include<linux/inetdevice.h>

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

void printmachdr(const char *pre, char *p, uint32_t len) {
	uint32_t i;
	if (len > 100) {
		len = 100;
	}
	printk(KERN_INFO);
	printk(pre);
	for (i = 0; i < len; i++) {
		if (i == 26 || i == 34 || i == 14) {
			printk("  ");
		}
		printk("%02hhx ", *p);
		p++;
	}
	printk("\n");
}

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
//	fl4->flowi4_scope = RTO_ONLINK;
	return ip_route_output_key(net, fl4);
}

//static int numipos = 1;

struct pcpu_dstats {
	u64			tx_packets;
	u64			tx_bytes;
	struct u64_stats_sync	syncp;
};

static void ipo_get_stats64(struct net_device *dev,
												   struct rtnl_link_stats64 *stats)
{
	int i;

	for_each_possible_cpu(i) {
		const struct pcpu_dstats *dstats;
		u64 tbytes, tpackets;
		unsigned int start;

		dstats = per_cpu_ptr(dev->dstats, i);
		do {
			start = u64_stats_fetch_begin_irq(&dstats->syncp);
			tbytes = dstats->tx_bytes;
			tpackets = dstats->tx_packets;
		} while (u64_stats_fetch_retry_irq(&dstats->syncp, start));
		stats->tx_bytes += tbytes;
		stats->tx_packets += tpackets;
	}
}

// Check include/linux/netdevice.h for enum rx_handler_result
static int ipo_rx(struct sk_buff *skb)
{
	struct iphdr *nh;
	struct optdata *optdata;
//	struct flowi4 fl4;
//	struct rtable *rt;
//	struct fib_result res;
	int err;
	char *pchar;
	struct net_device *dev = skb->dev;
	int len;
//	struct net *net = dev_net(dev);
//	const struct iphdr *iph = ip_hdr(skb);
//	struct ipo_net *ipon = net_generic(net, ipo_net_id);
//	if (iptunnel_pull_header(skb, 0, htons(ETH_P_IP), false)) {
//		goto drop;
//	}
	nh = (struct iphdr *)skb_network_header(skb);
	printk(KERN_WARNING "IPO skb->len %u 0.2\n", skb->len);
	skb_linearize_cow(skb);
	printk(KERN_INFO "head %p, data %p, tail %d, end %d, len %u, headroom %d, mac %d, network %d, transport %d, ip payload len %d\n", skb->head, skb->data, skb->tail, skb->end, skb->len, skb_headroom(skb), skb->mac_header, skb->network_header, skb->transport_header, ntohs(nh->tot_len));
	printk(KERN_INFO "IPO ipo_rx dev %s saddr %pI4, daddr %pI4, skb.proto %d, skb->pkt_type %d, nh->protocol %d, tos %d, ip_summed %d, nh->version %d, ntohs(nh->tot_len)=%d, nh->ihl*4=%d, nh->ttl=%d\n", dev->name, &nh->saddr, &nh->daddr, skb->protocol, skb->pkt_type, nh->protocol, nh->tos, skb->ip_summed, nh->version, ntohs(nh->tot_len), nh->ihl*4, nh->ttl);
//	if (skb_mac_header_was_set(skb)) {
//		printk(KERN_INFO "IPO ipo_rx mac header present, take off mac header\n");
////		skb->mac_header = skb->network_header;
////		__pskb_pull(skb, sizeof(struct ethhdr));
//#ifdef NET_SKBUFF_DATA_USES_OFFSET
//		skb->mac_header = ~0;
//#else
//		skb->mac_header = NULL;
//#endif
//		skb_pull(skb, ETH_HLEN);
//	}
	printk(KERN_WARNING "IPO skb->len %u 0.1\n", skb->len);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
//	printiphdr("IPO ipo_rx: ", (char *) skb_network_header(skb), ntohs(nh->tot_len));
	// TODO delete options?
	// TODO how to restore protocol
	nh->protocol = IPPROTO_ICMP;
	// search source ip prefix from route such as 192.168.1.0/24 via 10.0.0.2 dev ipo0 onlink
	// inet_dump_fib ?
//	memset(&fl4, 0, sizeof(fl4));
//	fl4.flowi4_oif = dev->ifindex;
//	fl4.flowi4_tos = RT_TOS(nh->tos);
//	fl4.flowi4_proto = nh->protocol;
//	fl4.fl4_gre_key = TUNNEL_NO_KEY;
//	err = fib_lookup(dev_net(dev), &fl4, &res);
//	if (err != 0) {
//		printk(KERN_WARNING "IPO ipo_rx fib_lookup error\n");
//		goto rx_error;
//	}
//	printk(KERN_INFO "IPO ipo_rx rt.rt_gateway %pI4 dev %s, saddr %pI4\n", &rt->rt_gateway, rt->dst.dev->name, &nh->saddr);
	printk(KERN_WARNING "IPO skb->len %u 0.0\n", skb->len);
	optdata = (struct optdata *)(skb_network_header(skb) + sizeof(struct iphdr) + sizeof(struct opthdr));
	if (nh->saddr == in_aton("10.0.0.2")) {
		pchar = (char*)&nh->saddr;
		pchar[0] = 192;
		pchar[1] = 168;
		pchar[2] = 1;
		pchar[3] = optdata->src;
		pchar[4] = 192;
		pchar[5] = 168;
		pchar[6] = 2;
		pchar[7] = optdata->dst;

	} else if (nh->saddr == in_aton("10.0.0.3")) {
		pchar = (char*)&nh->saddr;
		pchar[0] = 192;
		pchar[1] = 168;
		pchar[2] = 2;
		pchar[3] = optdata->src;
		pchar[4] = 192;
		pchar[5] = 168;
		pchar[6] = 1;
		pchar[7] = optdata->dst;
	}
	printk(KERN_WARNING "IPO skb->len %u 0\n", skb->len);
	nh->check = 0;
	nh->check = ip_fast_csum((u8 *)&nh, nh->ihl);
//	printmachdr("IPO ipo_rx mac ori: ", skb_mac_header(skb), ntohs(nh->tot_len) + sizeof(struct ethhdr));
//	skb_reset_mac_header(skb);
//	skb->protocol = eth_type_trans(skb, dev);
//	printmachdr("IPO ipo_rx mac after: ", skb_mac_header(skb), ntohs(nh->tot_len) + sizeof(struct ethhdr));
//	skb_reset_network_header(skb);
	printiphdr("IPO ipo_rx decode: ", (char *) skb_network_header(skb), ntohs(nh->tot_len));
//	skb_reset_mac_header(skb);
//	skb_scrub_packet(skb, false);
//	skb_postpull_rcsum(skb, eth_hdr(skb), ETH_HLEN);
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;
	printk(KERN_WARNING "IPO skb->len %u 1\n", skb->len);
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto drop;
	printk(KERN_WARNING "IPO skb->len %u 2\n", skb->len);
	if (!pskb_may_pull(skb, nh->ihl*4)) {
		printk(KERN_WARNING "IPO pskb_may_pull fail\n");
		goto drop;
	}
	printk(KERN_WARNING "IPO skb->len %u 3\n", skb->len);
	if (nh->ihl < 5 || nh->version != 4) {
		printk(KERN_WARNING "IPO pskb_may_pull fail\n");
		goto drop;
	}
	len = ntohs(nh->tot_len);
	if (skb->len < len) {
		printk(KERN_WARNING "IPO IPSTATS_MIB_INTRUNCATEDPKTS skb->len %u len %d fail\n", skb->len, len);
		goto drop;
	} else if (len < (nh->ihl*4)) {
		printk(KERN_WARNING "IPO ihl fail\n");
		goto drop;
	}

	err = netif_rx(skb);
	if (err != 0) {
		goto drop;
	}
//	err = IP_ECN_decapsulate(iph, skb);
//	if (unlikely(err)) {
////		net_info_ratelimited("non-ECT from %pI4 with TOS=%#x\n",
////							 &iph->saddr, iph->tos);
//		printk(KERN_INFO "IPO ipo_rx err %d\n", err);
//		if (err > 1) {
////			++ipon->dev->stats.rx_frame_errors;
////			++ipon->dev->stats.rx_errors;
//			goto drop;
//		}
//	}

//	tstats = this_cpu_ptr(tunnel->dev->tstats);
//	u64_stats_update_begin(&tstats->syncp);
//	tstats->rx_packets++;
//	tstats->rx_bytes += skb->len;
//	u64_stats_update_end(&tstats->syncp);

//	skb_scrub_packet(skb, false);
	printk(KERN_INFO "IPO ipo_rx gro_cells_receive skb->protocol %d\n", skb->protocol);
	printk(KERN_INFO "s %pI4, d %pI4, proto %d, ver %d, tl %d, ihl*4 %d, ttl=%d, csum %hu\n", &nh->saddr, &nh->daddr, nh->protocol, nh->version, ntohs(nh->tot_len), nh->ihl*4, nh->ttl, ip_fast_csum((u8 *)&nh, nh->ihl));
//	gro_cells_receive(&ipon->ipo_dev->gro_cells, skb);
	return 0;
drop:
	printk(KERN_WARNING "IPO rx_error\n");
	kfree_skb(skb);
	return 0;
}

static void ipo_err(struct sk_buff *skb, u32 info) {
//	struct iphdr *nh;
//	nh = (struct iphdr *)skb_network_header(skb);
//	printk(KERN_INFO "IPO ipo_err saddr %pI4, daddr %pI4, skb.proto %d, skb->pkt_type %d, nh->protocol %d, tos %d, ip_summed %d\n", &nh->saddr, &nh->daddr, skb->protocol, skb->pkt_type, nh->protocol, nh->tos, skb->ip_summed);
	printk(KERN_WARNING "IPO ipo_err\n");
}

const int IPPROTO_IPO = 143;

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
	struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);

	nf_reset(skb);

	err = ip_local_out(skb);
	if (likely(net_xmit_eval(err) == 0)) {
		u64_stats_update_begin(&dstats->syncp);
		dstats->tx_bytes += pkt_len;
		dstats->tx_packets++;
		u64_stats_update_end(&dstats->syncp);
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
	nh = (struct iphdr *)skb_network_header(skb);
	printmachdr("IPO ipo_xmit mac ori: ", skb_mac_header(skb), ntohs(nh->tot_len) + sizeof(struct ethhdr));
	if (ntohs(eth_hdr(skb)->h_proto) != ETH_P_IP) {
		printk(KERN_WARNING "Proto not ETH_P_IP");
//		goto tx_error;
	}
	if (unlikely(skb_headroom(skb) < overhead)) {
		printk(KERN_WARNING "IPO headroom %d too small\n", skb_headroom(skb));
		goto tx_error;
	}
	if (nh->ihl == 5) {
//		if (!dev->rx_handler)
//			printk(KERN_WARNING "IPO ipo_xmit rx handler should have registed");
		rt = skb_rtable(skb);
		if (rt == NULL) {
			printk(KERN_WARNING "IPO skb_rtable is null\n");
			goto tx_error;
		}
		printk(KERN_INFO "IPO rt.dst %pI4\n", &rt->rt_gateway);
		dst = rt->rt_gateway;
		printiphdr("IPO ipo_xmit ori: ", skb_network_header(skb), ntohs(nh->tot_len));
		printk(KERN_INFO "head %p, data %p, tail %d, end %d, len %d, headroom %d, mac %d, network %d, transport %d, ip payload len %d\n", skb->head, skb->data, skb->tail, skb->len, skb->end, skb_headroom(skb), skb->mac_header, skb->network_header, skb->transport_header, ntohs(nh->tot_len));
		if (skb_mac_header_was_set(skb)) {
#ifdef NET_SKBUFF_DATA_USES_OFFSET
			skb->mac_header = ~0;
#else
			skb->mac_header = NULL;
#endif
			skb_pull(skb, sizeof(struct ethhdr));
		}
		skb_set_network_header(skb, skb_network_offset(skb)-overhead);
		skb_push(skb, overhead);
		// copy ip headers ahead
		memcpy(skb_network_header(skb) - overhead, skb_network_header(skb), sizeof(struct iphdr));
		nh = (struct iphdr *)skb_network_header(skb);
		nh->ihl += overhead/4;
		nh->tot_len = htons(ntohs(nh->tot_len) + overhead);
		nh->protocol = IPPROTO_IPO;

		charp = skb_network_header(skb);
		opthdr = (struct opthdr *)(charp + sizeof(struct iphdr));
		opthdr->type = 40;
		opthdr->len = overhead;
		optdata = (struct optdata *)((char *)opthdr + sizeof(struct opthdr));
		// save last byte of src ip to opt src
		optdata->src = charp[15];
		optdata->dst = charp[19];
		nh->daddr = dst;
		//TODO checksum ?
//		printmachdr("IPO ipo_xmit mac new: ", skb_mac_header(skb), ntohs(nh->tot_len) + sizeof(struct ethhdr));
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
		nh->saddr = inet_select_addr(rt->dst.dev, rt_nexthop(rt, nh->daddr), RT_SCOPE_UNIVERSE);
//		printk(KERN_INFO "IPO rt.rt_gateway %pI4 dev %s, saddr %pI4\n", &rt->rt_gateway, rt->dst.dev->name, &nh->saddr);
//		nh->saddr = rt->rt_gateway;
		skb_dst_drop(skb);
		skb_dst_set(skb, &rt->dst);
		printiphdr("IPO ipo_xmit new: ", skb_network_header(skb), ntohs(nh->tot_len));
		printk(KERN_INFO "head %p, data %p, tail %d, end %d, len %d, headroom %d, mac %d, network %d, transport %d, ip payload len %d\n", skb->head, skb->data, skb->tail, skb->len, skb->end, skb_headroom(skb), skb->mac_header, skb->network_header, skb->transport_header, ntohs(nh->tot_len));
		iptunnel_xmit_ipo(skb, dev);
	} else {
		// TODO
	}
	printk(KERN_INFO "IPO tx_ok\n");
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
	dev->dstats = alloc_percpu(struct pcpu_dstats);
	if (!dev->dstats)
		return -ENOMEM;
	// preserve headroom for option fields.
	// It seems needed_headroom multiples by 4
	dev->needed_headroom = overhead;
	err = gro_cells_init(&ipo->gro_cells, dev);
	if (err) {
		free_percpu(dev->dstats);
		return err;
	}
	return 0;
}

static void ipo_dev_uninit(struct net_device *dev)
{
	struct ipo_dev *ipo = netdev_priv(dev);
	gro_cells_destroy(&ipo->gro_cells);
	free_percpu(dev->dstats);
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
//
//static void ipo_setup(struct net_device *dev)
//{
//	printk(KERN_INFO "IPO ipo_setup %s", dev->name);
//	ether_setup(dev);
//
//	/* Initialize the device structure. */
//	dev->netdev_ops = &ipo_netdev_ops;
//	dev->destructor = free_netdev;
//
//	dev->tx_queue_len = 0;
//	dev->type		= ARPHRD_NONE;
//	dev->flags |= IFF_NOARP;
//	dev->flags &= ~IFF_MULTICAST;
//	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
//	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
//	dev->features	|= NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_TSO;
//	dev->features	|= NETIF_F_HW_CSUM | NETIF_F_HIGHDMA | NETIF_F_LLTX;
//	dev->hw_features |= NETIF_F_GSO_SOFTWARE;
//	eth_hw_addr_random(dev);
//}

#define IPO_FEATURES (NETIF_F_SG |		\
		       NETIF_F_FRAGLIST |	\
		       NETIF_F_HIGHDMA |	\
		       NETIF_F_GSO_SOFTWARE |	\
		       NETIF_F_HW_CSUM |	\
			   NETIF_F_RXCSUM)

static void ipo_setup(struct net_device *dev)
{
	ether_setup(dev);
	dev->netdev_ops		= &ipo_netdev_ops;

	dev->type		= ARPHRD_TUNNEL;
	dev->flags		= IFF_NOARP;
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

static int __init ipo_init_module(void)
{
	int err = 0;
	if (inet_add_protocol(&net_ipo_protocol, IPPROTO_IPO) < 0) {
		pr_err("can't add protocol\n");
		return -EAGAIN;
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
	rtnl_link_unregister(&ipo_link_ops);
	inet_del_protocol(&net_ipo_protocol, IPPROTO_IPO);
	unregister_pernet_device(&ipo_net_ops);
	printk(KERN_INFO "IPO uninstalled\n");
}

module_init(ipo_init_module);
module_exit(ipo_cleanup_module);
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK("ipo");
