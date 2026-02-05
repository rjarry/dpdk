/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell International Ltd.
 */

#include <arpa/inet.h>
#include <sys/socket.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_lpm.h>
#include <rte_hash.h>
#include <rte_fbk_hash.h>
#include <rte_jhash.h>
#include <rte_hash_crc.h>

#include "rte_node_ip4_api.h"

#include "node_private.h"

static uint16_t
ip4_local_node_process_scalar(struct rte_graph *graph, struct rte_node *node,
			      void **objs, uint16_t nb_objs)
{
	struct rte_mbuf *mbuf;
	rte_edge_t next;
	uint32_t l4;
	int i;

	for (i = 0; i < nb_objs; i++) {
		mbuf = (struct rte_mbuf *)objs[i];
		l4 = mbuf->packet_type & RTE_PTYPE_L4_MASK;

		next = (l4 == RTE_PTYPE_L4_UDP)
				? RTE_NODE_IP4_LOCAL_NEXT_UDP4_INPUT
				: RTE_NODE_IP4_LOCAL_NEXT_PKT_DROP;

		rte_node_enqueue_deferred(graph, node, next, i);
	}

	return nb_objs;
}

static struct rte_node_register ip4_local_node = {
	.process = ip4_local_node_process_scalar,
	.name = "ip4_local",

	.nb_edges = RTE_NODE_IP4_LOCAL_NEXT_PKT_DROP + 1,
	.next_nodes = {
		[RTE_NODE_IP4_LOCAL_NEXT_UDP4_INPUT] = "udp4_input",
		[RTE_NODE_IP4_LOCAL_NEXT_PKT_DROP] = "pkt_drop",
	},
};

RTE_NODE_REGISTER(ip4_local_node);
