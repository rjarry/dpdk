#include <rte_ethdev.h>

#include "test.h"

static struct rte_device *
plug(const char *devargs)
{
	struct rte_eth_dev_info dev_info;
	struct rte_device *dev = NULL;
	struct rte_dev_iterator iter;
	uint16_t portid;

	if (rte_dev_probe(devargs) < 0)
		goto out;

	RTE_ETH_FOREACH_MATCHING_DEV(portid, devargs, &iter) {
		rte_eth_dev_info_get(portid, &dev_info);
		dev = dev_info.device;
		break;
	}
out:
	return dev;
}

static int
test_hotplug(void)
{
	while (true) {
		struct rte_device *dev1 = plug("net_null0");
		struct rte_device *dev2 = plug("net_null1");

		rte_dev_remove(dev2);
		rte_dev_remove(dev1);
	}

	return TEST_SUCCESS;
}

REGISTER_FAST_TEST(hotplug_autotest, true, true, test_hotplug);
