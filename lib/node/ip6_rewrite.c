/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell.
 */

#include <eal_export.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_vect.h>

#include "rte_node_ip6_api.h"

#include "ip6_rewrite_priv.h"
#include "node_private.h"

struct ip6_rewrite_node_ctx {
	/* Dynamic offset to mbuf priv1 */
	int mbuf_priv1_off;
};

static struct ip6_rewrite_node_main *ip6_rewrite_nm;

#define IP6_REWRITE_NODE_PRIV1_OFF(ctx) \
	(((struct ip6_rewrite_node_ctx *)ctx)->mbuf_priv1_off)

static uint16_t
ip6_rewrite_node_process(struct rte_graph *graph, struct rte_node *node,
			 void **objs, uint16_t nb_objs)
{
	struct rte_mbuf *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
	struct ip6_rewrite_nh_header *nh = ip6_rewrite_nm->nh;
	const int dyn = IP6_REWRITE_NODE_PRIV1_OFF(node->ctx);
	struct rte_ipv6_hdr *ip0, *ip1, *ip2, *ip3;
	rte_edge_t next0, next1, next2, next3;
	void *d0, *d1, *d2, *d3;
	uint16_t n_left_from;
	rte_xmm_t priv01;
	rte_xmm_t priv23;
	int i;

	rte_prefetch0(nh);

	pkts = (struct rte_mbuf **)objs;
	n_left_from = nb_objs;

	for (i = 0; i < 4 && i < n_left_from; i++)
		rte_prefetch0(pkts[i]);

	i = 0;
	/* Update Ethernet header of pkts */
	while (n_left_from >= 4) {
		if (likely(n_left_from > 7)) {
			/* Prefetch only next-mbuf struct and priv area.
			 * Data need not be prefetched as we only write.
			 */
			rte_prefetch0(pkts[4]);
			rte_prefetch0(pkts[5]);
			rte_prefetch0(pkts[6]);
			rte_prefetch0(pkts[7]);
		}

		mbuf0 = pkts[0];
		mbuf1 = pkts[1];
		mbuf2 = pkts[2];
		mbuf3 = pkts[3];

		pkts += 4;
		n_left_from -= 4;
		priv01.u64[0] = node_mbuf_priv1(mbuf0, dyn)->u;
		priv01.u64[1] = node_mbuf_priv1(mbuf1, dyn)->u;
		priv23.u64[0] = node_mbuf_priv1(mbuf2, dyn)->u;
		priv23.u64[1] = node_mbuf_priv1(mbuf3, dyn)->u;

		/* Update next_hop rewrite ethernet hdr on mbuf0 */
		d0 = rte_pktmbuf_mtod(mbuf0, void *);
		rte_memcpy(d0, nh[priv01.u16[0]].rewrite_data,
			   nh[priv01.u16[0]].rewrite_len);

		next0 = nh[priv01.u16[0]].tx_node;
		ip0 = (struct rte_ipv6_hdr *)((uint8_t *)d0 +
					      sizeof(struct rte_ether_hdr));
		ip0->hop_limits = priv01.u16[1] - 1;

		/* Update next_hop rewrite ethernet hdr on mbuf1 */
		d1 = rte_pktmbuf_mtod(mbuf1, void *);
		rte_memcpy(d1, nh[priv01.u16[4]].rewrite_data,
			   nh[priv01.u16[4]].rewrite_len);

		next1 = nh[priv01.u16[4]].tx_node;
		ip1 = (struct rte_ipv6_hdr *)((uint8_t *)d1 +
					      sizeof(struct rte_ether_hdr));
		ip1->hop_limits = priv01.u16[5] - 1;

		/* Update next_hop rewrite ethernet hdr on mbuf2 */
		d2 = rte_pktmbuf_mtod(mbuf2, void *);
		rte_memcpy(d2, nh[priv23.u16[0]].rewrite_data,
			   nh[priv23.u16[0]].rewrite_len);
		next2 = nh[priv23.u16[0]].tx_node;
		ip2 = (struct rte_ipv6_hdr *)((uint8_t *)d2 +
					      sizeof(struct rte_ether_hdr));
		ip2->hop_limits = priv23.u16[1] - 1;

		/* Update next_hop rewrite ethernet hdr on mbuf3 */
		d3 = rte_pktmbuf_mtod(mbuf3, void *);
		rte_memcpy(d3, nh[priv23.u16[4]].rewrite_data,
			   nh[priv23.u16[4]].rewrite_len);

		next3 = nh[priv23.u16[4]].tx_node;
		ip3 = (struct rte_ipv6_hdr *)((uint8_t *)d3 +
					      sizeof(struct rte_ether_hdr));
		ip3->hop_limits = priv23.u16[5] - 1;

		rte_node_enqueue_deferred(graph, node, next0, i);
		rte_node_enqueue_deferred(graph, node, next1, i + 1);
		rte_node_enqueue_deferred(graph, node, next2, i + 2);
		rte_node_enqueue_deferred(graph, node, next3, i + 3);
		i += 4;
	}

	while (n_left_from > 0) {
		mbuf0 = pkts[0];

		pkts += 1;
		n_left_from -= 1;

		d0 = rte_pktmbuf_mtod(mbuf0, void *);
		rte_memcpy(d0, nh[node_mbuf_priv1(mbuf0, dyn)->nh].rewrite_data,
			   nh[node_mbuf_priv1(mbuf0, dyn)->nh].rewrite_len);

		next0 = nh[node_mbuf_priv1(mbuf0, dyn)->nh].tx_node;
		ip0 = (struct rte_ipv6_hdr *)((uint8_t *)d0 +
					      sizeof(struct rte_ether_hdr));
		ip0->hop_limits = node_mbuf_priv1(mbuf0, dyn)->ttl - 1;

		rte_node_enqueue_deferred(graph, node, next0, i);
		i += 1;
	}

	return nb_objs;
}

static int
ip6_rewrite_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	int dyn;

	RTE_SET_USED(graph);
	RTE_BUILD_BUG_ON(sizeof(struct ip6_rewrite_node_ctx) > RTE_NODE_CTX_SZ);

	dyn = rte_node_mbuf_dynfield_register();
	if (dyn < 0)
		return -rte_errno;
	IP6_REWRITE_NODE_PRIV1_OFF(node->ctx) = dyn;

	node_dbg("ip6_rewrite", "Initialized ip6_rewrite node");

	return 0;
}

int
ip6_rewrite_set_next(uint16_t port_id, uint16_t next_index)
{
	if (ip6_rewrite_nm == NULL) {
		ip6_rewrite_nm = rte_zmalloc(
			"ip6_rewrite", sizeof(struct ip6_rewrite_node_main),
			RTE_CACHE_LINE_SIZE);
		if (ip6_rewrite_nm == NULL)
			return -ENOMEM;
	}
	ip6_rewrite_nm->next_index[port_id] = next_index;

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_node_ip6_rewrite_add, 23.07)
int
rte_node_ip6_rewrite_add(uint16_t next_hop, uint8_t *rewrite_data,
			 uint8_t rewrite_len, uint16_t dst_port)
{
	struct ip6_rewrite_nh_header *nh;

	if (next_hop >= RTE_GRAPH_IP6_REWRITE_MAX_NH)
		return -EINVAL;

	if (rewrite_len > RTE_GRAPH_IP6_REWRITE_MAX_LEN)
		return -EINVAL;

	if (ip6_rewrite_nm == NULL) {
		ip6_rewrite_nm = rte_zmalloc(
			"ip6_rewrite", sizeof(struct ip6_rewrite_node_main),
			RTE_CACHE_LINE_SIZE);
		if (ip6_rewrite_nm == NULL)
			return -ENOMEM;
	}

	/* Check if dst port doesn't exist as edge */
	if (!ip6_rewrite_nm->next_index[dst_port])
		return -EINVAL;

	/* Update next hop */
	nh = &ip6_rewrite_nm->nh[next_hop];

	memcpy(nh->rewrite_data, rewrite_data, rewrite_len);
	nh->tx_node = ip6_rewrite_nm->next_index[dst_port];
	nh->rewrite_len = rewrite_len;
	nh->enabled = true;

	return 0;
}

static struct rte_node_register ip6_rewrite_node = {
	.process = ip6_rewrite_node_process,
	.name = "ip6_rewrite",
	/* Default edge i.e '0' is pkt drop */
	.nb_edges = 1,
	.next_nodes = {
		[0] = "pkt_drop",
	},
	.init = ip6_rewrite_node_init,
};

struct rte_node_register *
ip6_rewrite_node_get(void)
{
	return &ip6_rewrite_node;
}

RTE_NODE_REGISTER(ip6_rewrite_node);
