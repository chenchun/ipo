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

#include <net/rtnetlink.h>
#include <net/dst.h>
#include <net/xfrm.h>

// ip option header
struct opthdr {
	uint8_t type;
	uint8_t len;
};

struct optdata {
	char src;
	char dst;
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


static int numipos = 1;

/* fake multicast ability */
static void set_multicast_list(struct net_device *dev)
{
}

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
static rx_handler_result_t ipo_rx(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct iphdr *nh;
	nh = (struct iphdr *)skb_network_header(skb);
	printk(KERN_INFO "IPO ipo_rx saddr %d, daddr %d\n", nh->saddr, nh->daddr);
	printiphdr("IPO ipo_rx: ", (char *) skb_network_header(skb), 24);
	return RX_HANDLER_PASS;
}

static netdev_tx_t ipo_xmit(struct sk_buff *skb, struct net_device *dev)
{
	int i, copied;
	int err;
	struct ethhdr *eth;
	struct iphdr *nh;
	char *start, *p;
	struct opthdr *opthdr;
	struct optdata *optdata;
	struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);

	eth = eth_hdr(skb);
	if (ntohs(eth->h_proto) != ETH_P_IP) {
		goto xmit_done;
	}
	nh = (struct iphdr *)skb_network_header(skb);
	if (unlikely(skb_headroom(skb) < overhead)) {
		goto xmit_done;
	}
	if (nh->ihl == 5) {
		printmachdr("IPO ipo_xmit mac ori: ", skb_mac_header(skb), ntohs(nh->tot_len) + sizeof(struct ethhdr));
//		printk(KERN_INFO "head %p, data %p, tail %d, end %d, len %d, headroom %d, mac %d, network %d, transport %d, ip payload len %d\n", skb->head, skb->data, skb->tail, skb->len, skb->end, skb_headroom(skb), skb->mac_header, skb->network_header, skb->transport_header, ntohs(nh->tot_len));
		// copy headers ahead
		if (skb_mac_header_was_set(skb)) {
//			printk(KERN_INFO "mac set\n");
			p = skb_mac_header(skb);
			start = p - overhead;
			copied = sizeof(struct iphdr) + sizeof(struct ethhdr);
			skb_set_mac_header(skb, skb_mac_offset(skb)-overhead);
		} else {
			p = skb_network_header(skb);
			start = p - overhead;
			copied = sizeof(struct iphdr);
		}
		skb_set_network_header(skb, skb_network_offset(skb)-overhead);
		skb_push(skb, overhead);
//		printk(KERN_INFO "head %p, data %p, tail %d, end %d, len %d, headroom %d, mac %d, network %d, transport %d, ip payload len %d\n", skb->head, skb->data, skb->tail, skb->len, skb->end, skb_headroom(skb), skb->mac_header, skb->network_header, skb->transport_header, ntohs(nh->tot_len));
//		printk(KERN_INFO "start %p, p %p, copied %d\n", start, p, copied);
		for (i = 0; i < copied; i++) {
			*start++ = *p++;
		}
		nh = (struct iphdr *)skb_network_header(skb);
//		printmachdr("IPO ipo_xmit mac int: ", skb_mac_header(skb), 60);
		nh->ihl += overhead/4;
		nh->tot_len = htons(ntohs(nh->tot_len) + overhead);

		start = skb_network_header(skb);
		opthdr = (struct opthdr *)(start + sizeof(struct iphdr));
		opthdr->type = 40;
		opthdr->len = overhead;
		optdata = (struct optdata *)((char *)opthdr + sizeof(struct opthdr));
		// save last byte of src ip to opt src
//		optdata->src = start[15];
		optdata->dst = start[19];
		//TODO remove following lines and replace them with src ip and dst ip
		start = skb_network_header(skb);
		start[14] = 2;
		start[18] = 2;
		//TODO checksum ?
		printmachdr("IPO ipo_xmit mac new: ", skb_mac_header(skb), ntohs(nh->tot_len) + sizeof(struct ethhdr));
//		printiphdr("IPO ipo_xmit new: ", skb_network_header(skb), ntohs(nh->tot_len) );
		err = ip_local_out(skb);
		if (likely(net_xmit_eval(err) == 0)) {
			goto xmit_done;
		} else {
			
		}
	} else {
		// TODO
	}
xmit_done:
	u64_stats_update_begin(&dstats->syncp);
	dstats->tx_packets++;
	dstats->tx_bytes += skb->len;
	u64_stats_update_end(&dstats->syncp);
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int ipo_newlink(struct net *net, struct net_device *dev,
					   struct nlattr *tb[], struct nlattr *data[])
{
	int err;
	err = netdev_rx_handler_register(dev, ipo_rx, NULL);
	if (err < 0)
		return err;
	return register_netdevice(dev);
}

static int ipo_dev_init(struct net_device *dev)
{
	dev->dstats = alloc_percpu(struct pcpu_dstats);
	if (!dev->dstats)
		return -ENOMEM;
	// preserve headroom for option fields.
	// It seems needed_headroom multiples by 4
	dev->needed_headroom = overhead;
	return 0;
}

static void ipo_dev_uninit(struct net_device *dev)
{
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
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_rx_mode	= set_multicast_list,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_get_stats64	= ipo_get_stats64,
	.ndo_change_carrier	= ipo_change_carrier,
};

static void ipo_setup(struct net_device *dev)
{
	ether_setup(dev);

	/* Initialize the device structure. */
	dev->netdev_ops = &ipo_netdev_ops;
	dev->destructor = free_netdev;

	/* Fill in device structure with ethernet-generic values. */
	dev->tx_queue_len = 0;
	dev->flags |= IFF_NOARP;
	dev->flags &= ~IFF_MULTICAST;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	dev->features	|= NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_TSO;
	dev->features	|= NETIF_F_HW_CSUM | NETIF_F_HIGHDMA | NETIF_F_LLTX;
	eth_hw_addr_random(dev);
}

static int ipo_validate(struct nlattr *tb[], struct nlattr *data[])
{
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
};

/* Number of ipo devices to be set up by this module. */
module_param(numipos, int, 0);
MODULE_PARM_DESC(numipos, "Number of ipo pseudo devices");

static int __init ipo_init_one(void)
{
	struct net_device *dev_ipo;
	int err;

	dev_ipo = alloc_netdev(0, "ipo%d", ipo_setup);
	if (!dev_ipo)
		return -ENOMEM;

	dev_ipo->rtnl_link_ops = &ipo_link_ops;
	err = register_netdevice(dev_ipo);
	if (err < 0)
		goto err;
	return 0;

	err:
	free_netdev(dev_ipo);
	return err;
}

static int __init ipo_init_module(void)
{
	int i, err = 0;

	rtnl_lock();
	err = __rtnl_link_register(&ipo_link_ops);

	for (i = 0; i < numipos && !err; i++) {
		err = ipo_init_one();
		cond_resched();
	}
	if (err < 0)
		__rtnl_link_unregister(&ipo_link_ops);
	rtnl_unlock();
	printk(KERN_INFO "IPO installed overhead %d\n", overhead);
	return err;
}

static void __exit ipo_cleanup_module(void)
{
	rtnl_link_unregister(&ipo_link_ops);
	printk(KERN_INFO "IPO uninstalled\n");
}

module_init(ipo_init_module);
module_exit(ipo_cleanup_module);
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK("ipo");
