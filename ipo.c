//
// Created by ramichen on 19-4-19.
//

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define DRV_NAME	"ipo"
#define DRV_VERSION	"1.0"
#define DRV_DESCRIPTION	"IP option device driver"
#define DRV_COPYRIGHT	"(C) 2019-2020 Chun Chen <ramichen@tencent.com>"

#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/slab.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/u64_stats_sync.h>
#include <linux/etherdevice.h>

#include <net/rtnetlink.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <linux/percpu-defs.h>

int tun_addr = 2;

struct ipo_priv {
	atomic64_t		dropped;
};

struct pcpu_dstats {
	u64			tx_packets;
	u64			tx_bytes;
	struct u64_stats_sync	syncp;
};

static int ipo_dev_init(struct net_device *dev)
{
//	struct ipo_priv *priv = netdev_priv(dev);

	dev->dstats = netdev_alloc_pcpu_stats(struct pcpu_dstats);
	if (!dev->dstats)
		return -ENOMEM;

//	dev->dev.parent = &ipo_parent;
	return 0;
}

static void ipo_dev_uninit(struct net_device *dev)
{
	free_percpu(dev->dstats);
}

static netdev_tx_t ipo_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);

	u64_stats_update_begin(&dstats->syncp);
	dstats->tx_packets++;
	dstats->tx_bytes += skb->len;
	u64_stats_update_end(&dstats->syncp);

	skb_tx_timestamp(skb);
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

/* fake multicast ability */
static void set_multicast_list(struct net_device *dev)
{
}

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

static int ipo_newlink(struct net *src_net, struct net_device *dev,
						struct nlattr *tb[], struct nlattr *data[],
						struct netlink_ext_ack *extack)
{
	int err;
	if (!dev) {
		printk(KERN_INFO "IPO ipo_newlink dev not nil\n");
	}
	if (tb[IFLA_ADDRESS] == NULL)
		eth_hw_addr_random(dev);

	if (tb[IFLA_IFNAME])
		nla_strlcpy(dev->name, tb[IFLA_IFNAME], IFNAMSIZ);
	else
		snprintf(dev->name, IFNAMSIZ, DRV_NAME "%%d");

	err = register_netdevice(dev);
	if (err < 0)
		goto err_register_dev;

	netif_carrier_off(dev);
err_register_dev:
	/* nothing to do */
	return err;
}

static void ipo_dellink(struct net_device *dev, struct list_head *head)
{
	unregister_netdevice_queue(dev, head);
	return;
}


static void ipo_dev_free(struct net_device *dev)
{
	free_percpu(dev->vstats);
}

static int ipo_validate(struct nlattr *tb[], struct nlattr *data[],
						 struct netlink_ext_ack *extack)
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	return 0;
}

static void ipo_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->priv_flags &= ~IFF_TX_SKB_SHARING;
	dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->priv_flags |= IFF_PHONY_HEADROOM;

	dev->netdev_ops = &ipo_netdev_ops;
//	dev->ethtool_ops = &veth_ethtool_ops;
	dev->features |= NETIF_F_LLTX;
//	dev->features |= VETH_FEATURES;
	dev->vlan_features = dev->features &
						 ~(NETIF_F_HW_VLAN_CTAG_TX |
						   NETIF_F_HW_VLAN_STAG_TX |
						   NETIF_F_HW_VLAN_CTAG_RX |
						   NETIF_F_HW_VLAN_STAG_RX);
	dev->needs_free_netdev = true;
	dev->priv_destructor = ipo_dev_free;
	dev->max_mtu = ETH_MAX_MTU;

//	dev->hw_features = VETH_FEATURES;
//	dev->hw_enc_features = VETH_FEATURES;
	dev->mpls_features = NETIF_F_HW_CSUM | NETIF_F_GSO_SOFTWARE;
}

static struct net *ipo_get_link_net(const struct net_device *dev)
{
	return dev_net(dev);
}

static struct rtnl_link_ops ipo_link_ops = {
	.kind		= DRV_NAME,
	.priv_size	= sizeof(struct ipo_priv),
	.setup		= ipo_setup,
	.validate	= ipo_validate,
	.newlink	= ipo_newlink,
	.dellink	= ipo_dellink,
//	.policy		= veth_policy,
//	.maxtype	= VETH_INFO_MAX,
	.get_link_net	= ipo_get_link_net,
};

static __init int ipo_init(void)
{
	printk(KERN_INFO "IPO installed\n");
	return rtnl_link_register(&ipo_link_ops);
}

static __exit void ipo_cleanup(void)
{
	printk(KERN_INFO "IPO uninstalled\n");
	rtnl_link_unregister(&ipo_link_ops);
}

module_init(ipo_init);
module_exit(ipo_cleanup);
module_param(tun_addr, int, 0644);
MODULE_PARM_DESC(tun_addr, "An integer");

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");

/*
 *  This module uses /dev/ipo.  The MODULE_SUPPORTED_DEVICE macro might
 *  be used in the future to help automatic configuration of modules, but is
 *  currently unused other than for documentation purposes.
 */
MODULE_SUPPORTED_DEVICE("ipo");