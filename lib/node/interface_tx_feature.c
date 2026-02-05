/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell International Ltd.
 */

#include <arpa/inet.h>
#include <sys/socket.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph_feature_arc_worker.h>
#include <rte_malloc.h>

#include "rte_node_ip4_api.h"
#include "node_private.h"
#include "interface_tx_feature_priv.h"

/*
 * @internal array for mapping port to next node index
 */
struct if_tx_feature_node_main  {
	uint16_t next_index[RTE_MAX_ETHPORTS];
};

static struct if_tx_feature_node_main *if_tx_feature_nm;

int
if_tx_feature_node_set_next(uint16_t port_id, uint16_t next_index)
{
	if (if_tx_feature_nm == NULL) {
		if_tx_feature_nm = rte_zmalloc(
			"if_tx_feature_nm", sizeof(struct if_tx_feature_node_main),
			RTE_CACHE_LINE_SIZE);
		if (if_tx_feature_nm == NULL)
			return -ENOMEM;
	}
	if_tx_feature_nm->next_index[port_id] = next_index;

	return 0;
}

static int
if_tx_feature_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	return 0;
}

static uint16_t
if_tx_feature_node_process(struct rte_graph *graph, struct rte_node *node,
			   void **objs, uint16_t nb_objs)
{
	struct rte_mbuf *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
	rte_edge_t next0, next1, next2, next3;
	uint16_t n_left_from;
	int i;

	n_left_from = nb_objs;
	pkts = (struct rte_mbuf **)objs;

	i = 0;
	while (n_left_from > 4) {
		if (likely(n_left_from > 7)) {
			/* Prefetch next mbuf */
			rte_prefetch0(objs[4]);
			rte_prefetch0(objs[5]);
			rte_prefetch0(objs[6]);
			rte_prefetch0(objs[7]);
		}
		mbuf0 = pkts[0];
		mbuf1 = pkts[1];
		mbuf2 = pkts[2];
		mbuf3 = pkts[3];
		pkts += 4;
		n_left_from -= 4;

		/* port-tx node starts from next edge 1*/
		next0 = if_tx_feature_nm->next_index[mbuf0->port];
		next1 = if_tx_feature_nm->next_index[mbuf1->port];
		next2 = if_tx_feature_nm->next_index[mbuf2->port];
		next3 = if_tx_feature_nm->next_index[mbuf3->port];

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

		next0 = if_tx_feature_nm->next_index[mbuf0->port];

		rte_node_enqueue_deferred(graph, node, next0, i);
		i += 1;
	}

	return nb_objs;
}

static struct rte_node_register if_tx_feature_node = {
	.process = if_tx_feature_node_process,
	.init = if_tx_feature_node_init,
	.name = "interface_tx",
	.nb_edges = 1,
	.next_nodes = {
		[0] = "pkt_drop",
	},
};

struct rte_node_register *
if_tx_feature_node_get(void)
{
	return &if_tx_feature_node;
}

RTE_NODE_REGISTER(if_tx_feature_node);

/* if_tx feature node */
struct rte_graph_feature_register if_tx_feature = {
	.feature_name = RTE_IP4_OUTPUT_END_FEATURE_NAME,
	.arc_name = RTE_IP4_OUTPUT_FEATURE_ARC_NAME,
	.feature_process_fn = if_tx_feature_node_process,
	.feature_node = &if_tx_feature_node,
};
