/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Robin Jarry
 */

#include <rte_ip6.h>

#include "test.h"

static const struct in6_addr bcast_addr = RTE_IPV6_ADDR_BCAST_INIT;
static const struct in6_addr zero_addr = IN6ADDR_ANY_INIT;

static int
test_ipv6_addr_mask(void)
{
	const struct in6_addr masked_3 = RTE_IPV6(0xe000, 0, 0, 0, 0, 0, 0, 0);
	const struct in6_addr masked_42 = RTE_IPV6(0xffff, 0xffff, 0xffc0, 0, 0, 0, 0, 0);
	const struct in6_addr masked_85 =
		RTE_IPV6(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xf800, 0, 0);
	const struct in6_addr masked_127 =
		RTE_IPV6(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xfffe);
	struct in6_addr ip;

	ip = bcast_addr;
	rte_ipv6_addr_mask(&ip, 0);
	TEST_ASSERT(IN6_ARE_ADDR_EQUAL(&ip, &zero_addr), "");
	TEST_ASSERT_EQUAL(rte_ipv6_mask_depth(&zero_addr), 0, "");

	ip = bcast_addr;
	rte_ipv6_addr_mask(&ip, 3);
	TEST_ASSERT(IN6_ARE_ADDR_EQUAL(&ip, &masked_3), "");
	TEST_ASSERT_EQUAL(rte_ipv6_mask_depth(&masked_3), 3, "");

	ip = bcast_addr;
	rte_ipv6_addr_mask(&ip, 42);
	TEST_ASSERT(IN6_ARE_ADDR_EQUAL(&ip, &masked_42), "");
	TEST_ASSERT_EQUAL(rte_ipv6_mask_depth(&masked_42), 42, "");

	ip = bcast_addr;
	rte_ipv6_addr_mask(&ip, 85);
	TEST_ASSERT(IN6_ARE_ADDR_EQUAL(&ip, &masked_85), "");
	TEST_ASSERT_EQUAL(rte_ipv6_mask_depth(&masked_85), 85, "");

	ip = bcast_addr;
	rte_ipv6_addr_mask(&ip, 127);
	TEST_ASSERT(IN6_ARE_ADDR_EQUAL(&ip, &masked_127), "");
	TEST_ASSERT_EQUAL(rte_ipv6_mask_depth(&masked_127), 127, "");

	ip = bcast_addr;
	rte_ipv6_addr_mask(&ip, 128);
	TEST_ASSERT(IN6_ARE_ADDR_EQUAL(&ip, &bcast_addr), "");
	TEST_ASSERT_EQUAL(rte_ipv6_mask_depth(&bcast_addr), 128, "");

	const struct in6_addr holed_mask =
		RTE_IPV6(0xffff, 0xffff, 0xffff, 0xefff, 0xffff, 0xffff, 0xffff, 0xffff);
	TEST_ASSERT_EQUAL(rte_ipv6_mask_depth(&holed_mask), 51, "");

	return TEST_SUCCESS;
}

static int
test_ipv6_addr_eq_prefix(void)
{
	const struct in6_addr ip1 =
		RTE_IPV6(0x2a01, 0xcb00, 0x0254, 0x3300, 0x1b9f, 0x8071, 0x67cd, 0xbf20);
	const struct in6_addr ip2 =
		RTE_IPV6(0x2a01, 0xcb00, 0x0254, 0x3300, 0x6239, 0xe1f4, 0x7a0b, 0x2371);
	const struct in6_addr ip3 =
		RTE_IPV6(0xfd10, 0x0039, 0x0208, 0x0001, 0x0000, 0x0000, 0x0000, 0x1008);

	TEST_ASSERT(rte_ipv6_addr_eq_prefix(&ip1, &ip2, 1), "");
	TEST_ASSERT(rte_ipv6_addr_eq_prefix(&ip1, &ip2, 37), "");
	TEST_ASSERT(rte_ipv6_addr_eq_prefix(&ip1, &ip2, 64), "");
	TEST_ASSERT(!rte_ipv6_addr_eq_prefix(&ip1, &ip2, 112), "");
	TEST_ASSERT(rte_ipv6_addr_eq_prefix(&ip1, &ip3, 0), "");
	TEST_ASSERT(!rte_ipv6_addr_eq_prefix(&ip1, &ip3, 13), "");

	return TEST_SUCCESS;
}

static int
test_net_ipv6(void)
{
	TEST_ASSERT_SUCCESS(test_ipv6_addr_mask(), "");
	TEST_ASSERT_SUCCESS(test_ipv6_addr_eq_prefix(), "");
	return TEST_SUCCESS;
}

REGISTER_FAST_TEST(net_ipv6_autotest, true, true, test_net_ipv6);
