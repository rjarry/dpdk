/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2020 Marvell.
 */

#include <stdalign.h>

#include <rte_graph.h>
#include <rte_graph_worker.h>

#include "pkt_cls_priv.h"
#include "node_private.h"
#include "rte_node_pkt_cls_api.h"

/* Next node for each ptype, default is '0' is "pkt_drop" */
static const alignas(RTE_CACHE_LINE_SIZE) uint8_t p_nxt[256] = {
	[RTE_PTYPE_L3_IPV4] = RTE_NODE_PKT_CLS_NEXT_IP4_LOOKUP,

	[RTE_PTYPE_L3_IPV4_EXT] = RTE_NODE_PKT_CLS_NEXT_IP4_LOOKUP,

	[RTE_PTYPE_L3_IPV4_EXT_UNKNOWN] = RTE_NODE_PKT_CLS_NEXT_IP4_LOOKUP,

	[RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L2_ETHER] =
		RTE_NODE_PKT_CLS_NEXT_IP4_LOOKUP,

	[RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L2_ETHER] =
		RTE_NODE_PKT_CLS_NEXT_IP4_LOOKUP,

	[RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L2_ETHER] =
		RTE_NODE_PKT_CLS_NEXT_IP4_LOOKUP,

	[RTE_PTYPE_L3_IPV6] = RTE_NODE_PKT_CLS_NEXT_IP6_LOOKUP,

	[RTE_PTYPE_L3_IPV6_EXT] = RTE_NODE_PKT_CLS_NEXT_IP6_LOOKUP,

	[RTE_PTYPE_L3_IPV6_EXT_UNKNOWN] = RTE_NODE_PKT_CLS_NEXT_IP6_LOOKUP,

	[RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L2_ETHER] = RTE_NODE_PKT_CLS_NEXT_IP6_LOOKUP,

	[RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L2_ETHER] = RTE_NODE_PKT_CLS_NEXT_IP6_LOOKUP,

	[RTE_PTYPE_L3_IPV6_EXT_UNKNOWN | RTE_PTYPE_L2_ETHER] =
		RTE_NODE_PKT_CLS_NEXT_IP6_LOOKUP,
};

static uint16_t
pkt_cls_node_process(struct rte_graph *graph, struct rte_node *node,
		     void **objs, uint16_t nb_objs)
{
	struct rte_mbuf *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
	uint8_t l0, l1, l2, l3;
	uint16_t n_left_from;
	uint32_t i;

	pkts = (struct rte_mbuf **)objs;
	n_left_from = nb_objs;

	for (i = OBJS_PER_CLINE; i < RTE_GRAPH_BURST_SIZE; i += OBJS_PER_CLINE)
		rte_prefetch0(&objs[i]);

#if RTE_GRAPH_BURST_SIZE > 64
	for (i = 0; i < 4 && i < n_left_from; i++)
		rte_prefetch0(pkts[i]);
#endif

	i = 0;
	while (n_left_from >= 4) {
#if RTE_GRAPH_BURST_SIZE > 64
		if (likely(n_left_from > 7)) {
			rte_prefetch0(pkts[4]);
			rte_prefetch0(pkts[5]);
			rte_prefetch0(pkts[6]);
			rte_prefetch0(pkts[7]);
		}
#endif

		mbuf0 = pkts[0];
		mbuf1 = pkts[1];
		mbuf2 = pkts[2];
		mbuf3 = pkts[3];
		pkts += 4;
		n_left_from -= 4;

		l0 = mbuf0->packet_type &
			(RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK);
		l1 = mbuf1->packet_type &
			(RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK);
		l2 = mbuf2->packet_type &
			(RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK);
		l3 = mbuf3->packet_type &
			(RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK);

		rte_node_enqueue_deferred(graph, node, p_nxt[l0], i);
		rte_node_enqueue_deferred(graph, node, p_nxt[l1], i + 1);
		rte_node_enqueue_deferred(graph, node, p_nxt[l2], i + 2);
		rte_node_enqueue_deferred(graph, node, p_nxt[l3], i + 3);
		i += 4;
	}

	while (n_left_from > 0) {
		mbuf0 = pkts[0];

		pkts += 1;
		n_left_from -= 1;

		l0 = mbuf0->packet_type &
			(RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK);

		rte_node_enqueue_deferred(graph, node, p_nxt[l0], i);
		i += 1;
	}

	return nb_objs;
}

/* Packet Classification Node */
struct rte_node_register pkt_cls_node = {
	.process = pkt_cls_node_process,
	.name = "pkt_cls",

	.nb_edges = RTE_NODE_PKT_CLS_NEXT_MAX,
	.next_nodes = {
		/* Pkt drop node starts at '0' */
		[RTE_NODE_PKT_CLS_NEXT_PKT_DROP] = "pkt_drop",
		[RTE_NODE_PKT_CLS_NEXT_IP4_LOOKUP] = "ip4_lookup",
		[RTE_NODE_PKT_CLS_NEXT_IP6_LOOKUP] = "ip6_lookup",
		[RTE_NODE_PKT_CLS_NEXT_IP4_LOOKUP_FIB] = "ip4_lookup_fib",
		[RTE_NODE_PKT_CLS_NEXT_IP6_LOOKUP_FIB] = "ip6_lookup_fib",
	},
};
RTE_NODE_REGISTER(pkt_cls_node);
