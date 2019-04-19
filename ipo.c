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

static int __init ipo_init(void)
{
	int ret = 0;
	printk(KERN_INFO "IPO installed\n");
	return ret;
}

static void ipo_cleanup(void)
{
	printk(KERN_INFO "IPO uninstalled\n");
}

module_init(ipo_init);
module_exit(ipo_cleanup);
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");

/*
 *  This module uses /dev/ipo.  The MODULE_SUPPORTED_DEVICE macro might
 *  be used in the future to help automatic configuration of modules, but is
 *  currently unused other than for documentation purposes.
 */
MODULE_SUPPORTED_DEVICE("ipo");