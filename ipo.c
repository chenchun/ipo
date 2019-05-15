#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/slab.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/u64_stats_sync.h>
#include <linux/etherdevice.h>
#include <linux/percpu-defs.h>

#include <net/rtnetlink.h>
#include <net/dst.h>
#include <net/xfrm.h>

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
	struct iphdr *nh = (struct iphdr *)skb_network_header(skb);
	printk(KERN_INFO "IPO ipo_rx saddr %d, daddr %d\n", nh->saddr, nh->daddr);
	return RX_HANDLER_PASS;
}

static netdev_tx_t ipo_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);

	u64_stats_update_begin(&dstats->syncp);
	dstats->tx_packets++;
	dstats->tx_bytes += skb->len;
	u64_stats_update_end(&dstats->syncp);
	struct iphdr *nh = (struct iphdr *)skb_network_header(skb);
	printk(KERN_INFO "IPO ipo_xmit saddr %d, daddr %d\n", nh->saddr, nh->daddr);
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int ipo_dev_init(struct net_device *dev)
{
	dev->dstats = alloc_percpu(struct pcpu_dstats);
	if (!dev->dstats)
		return -ENOMEM;

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
	netdev_rx_handler_register(dev_ipo, ipo_rx, NULL);
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
	printk(KERN_INFO "IPO installed\n");
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
