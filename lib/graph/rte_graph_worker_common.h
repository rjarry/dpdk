/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef _RTE_GRAPH_WORKER_COMMON_H_
#define _RTE_GRAPH_WORKER_COMMON_H_

/**
 * @file rte_graph_worker_common.h
 *
 * This API allows a worker thread to walk over a graph and nodes to create,
 * process, enqueue and move streams of objects to the next nodes.
 */

#include <assert.h>
#include <stdalign.h>
#include <stddef.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_memcpy.h>
#include <rte_memory.h>

#include "rte_graph.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Graph worker models */
/* When adding a new graph model entry, update rte_graph_model_is_valid() implementation. */
#define RTE_GRAPH_MODEL_RTC 0 /**< Run-To-Completion model. It is the default model. */
#define RTE_GRAPH_MODEL_MCORE_DISPATCH 1
/**< Dispatch model to support cross-core dispatching within core affinity. */
#define RTE_GRAPH_MODEL_DEFAULT RTE_GRAPH_MODEL_RTC /**< Default graph model. */

/**
 * @internal
 *
 * Singly-linked list head for graph schedule run-queue.
 */
SLIST_HEAD(rte_graph_rq_head, rte_graph);

/**
 * @internal
 *
 * Data structure to hold graph data.
 */
struct __rte_cache_aligned rte_graph {
	/* Fast path area. */
	uint32_t tail;		     /**< Tail of circular buffer. */
	uint32_t head;		     /**< Head of circular buffer. */
	uint32_t cir_mask;	     /**< Circular buffer wrap around mask. */
	rte_node_t nb_nodes;	     /**< Number of nodes in the graph. */
	rte_graph_off_t *cir_start;  /**< Pointer to circular buffer. */
	rte_graph_off_t nodes_start; /**< Offset at which node memory starts. */
	uint8_t model;		     /**< graph model */
	uint8_t reserved1;	     /**< Reserved for future use. */
	uint16_t reserved2;	     /**< Reserved for future use. */
	union {
		/* Fast schedule area for mcore dispatch model */
		struct {
			alignas(RTE_CACHE_LINE_SIZE) struct rte_graph_rq_head *rq;
				/* The run-queue */
			struct rte_graph_rq_head rq_head; /* The head for run-queue list */

			unsigned int lcore_id;  /**< The graph running Lcore. */
			struct rte_ring *wq;    /**< The work-queue for pending streams. */
			struct rte_mempool *mp; /**< The mempool for scheduling streams. */
			packets_enqueued_cb notify_cb; /**< Callback when packet crosses lcores. */
			uint64_t cb_priv;       /**< Opaque parameter for notify_cb. */
		} dispatch; /** Only used by dispatch model */
	};
	SLIST_ENTRY(rte_graph) next;   /* The next for rte_graph list */
	/* End of Fast path area.*/
	rte_graph_t id;	/**< Graph identifier. */
	int socket;	/**< Socket ID where memory is allocated. */
	char name[RTE_GRAPH_NAMESIZE];	/**< Name of the graph. */
	bool pcap_enable;	        /**< Pcap trace enabled. */
	/** Number of packets captured per core. */
	uint64_t nb_pkt_captured;
	/** Number of packets to capture per core. */
	uint64_t nb_pkt_to_capture;
	char pcap_filename[RTE_GRAPH_PCAP_FILE_SZ];  /**< Pcap filename. */
	uint64_t fence;			/**< Fence. */
};

/**
 * @internal
 *
 * Cached destination stream slot for rte_node_next_stream_enqueue().
 */
struct rte_node_stream_slot {
	void **to_next;		/**< Dest stream ptr, NULL = lazy. */
	rte_edge_t edge;	/**< Next edge index. */
	uint16_t count;		/**< Objects enqueued in this slot. */
};

/**
 * @internal
 *
 * Data structure to hold node data.
 */
struct __rte_cache_aligned rte_node {
	/* Slow path area  */
	uint64_t fence;		/**< Fence. */
	rte_graph_off_t next;	/**< Index to next node. */
	rte_node_t id;		/**< Node identifier. */
	rte_node_t parent_id;	/**< Parent Node identifier. */
	rte_edge_t nb_edges;	/**< Number of edges from this node. */
	uint32_t realloc_count;	/**< Number of times realloced. */

	char parent[RTE_NODE_NAMESIZE];	/**< Parent node name. */
	char name[RTE_NODE_NAMESIZE];	/**< Name of the node. */

	/** Original process function when pcap is enabled. */
	rte_node_process_t original_process;

	/** Fast schedule area for mcore dispatch model. */
	union {
		alignas(RTE_CACHE_LINE_MIN_SIZE) struct {
			unsigned int lcore_id;  /**< Node running lcore. */
			uint64_t total_sched_objs; /**< Number of objects scheduled. */
			uint64_t total_sched_fail; /**< Number of scheduled failure. */
			struct rte_graph *graph;  /**< Graph corresponding to lcore_id. */
		} dispatch;
	};

	/** Fast path area cache line 1. */
	alignas(RTE_CACHE_LINE_MIN_SIZE)
	rte_graph_off_t xstat_off; /**< Offset to xstat counters. */

	struct rte_node_stream_slot stream_slots[RTE_NODE_STREAM_SLOTS_MAX];
	uint8_t stream_slot_count;	/**< Number of active stream slots. */

	/** Fast path area cache line 2. */
	__extension__ struct __rte_cache_aligned {
#define RTE_NODE_CTX_SZ 16
		union {
			uint8_t ctx[RTE_NODE_CTX_SZ];
			__extension__ struct {
				void *ctx_ptr;
				void *ctx_ptr2;
			};
		}; /**< Node Context. */
		uint16_t size;		/**< Total number of objects available. */
		uint16_t idx;		/**< Number of objects used. */
		rte_graph_off_t off;	/**< Offset of node in the graph reel. */
		uint64_t total_cycles;	/**< Cycles spent in this node. */
		uint64_t total_calls;	/**< Calls done to this node. */
		uint64_t total_objs;	/**< Objects processed by this node. */
		union {
			void **objs;	   /**< Array of object pointers. */
			uint64_t objs_u64;
		};
		union {
			rte_node_process_t process; /**< Process function. */
			uint64_t process_u64;
		};
		alignas(RTE_CACHE_LINE_MIN_SIZE) struct rte_node *nodes[]; /**< Next nodes. */
	};
};

static_assert(offsetof(struct rte_node, nodes) - offsetof(struct rte_node, ctx)
	== RTE_CACHE_LINE_MIN_SIZE, "rte_node fast path area must fit in 64 bytes");

/**
 * @internal
 *
 * Allocate a stream of objects.
 *
 * If stream already exists then re-allocate it to a larger size.
 *
 * @param graph
 *   Pointer to the graph object.
 * @param node
 *   Pointer to the node object.
 */
void __rte_node_stream_alloc(struct rte_graph *graph, struct rte_node *node);

/**
 * @internal
 *
 * Allocate a stream with requested number of objects.
 *
 * If stream already exists then re-allocate it to a larger size.
 *
 * @param graph
 *   Pointer to the graph object.
 * @param node
 *   Pointer to the node object.
 * @param req_size
 *   Number of objects to be allocated.
 */
void __rte_node_stream_alloc_size(struct rte_graph *graph,
				  struct rte_node *node, uint16_t req_size);

/* Fast path helper functions */

static inline void __rte_node_next_stream_enqueue_flush(struct rte_graph *, struct rte_node *);

/**
 * @internal
 *
 * Enqueue a given node to the tail of the graph reel.
 *
 * @param graph
 *   Pointer Graph object.
 * @param node
 *   Pointer to node object to be enqueued.
 */
static __rte_always_inline void
__rte_node_process(struct rte_graph *graph, struct rte_node *node)
{
	uint64_t start;
	uint16_t rc;
	void **objs;

	RTE_ASSERT(node->fence == RTE_GRAPH_FENCE);
	objs = node->objs;
	rte_prefetch0(objs);
	for (uint8_t j = 0; j < node->stream_slot_count; j++) {
		node->stream_slots[j].to_next = NULL;
		node->stream_slots[j].count = 0;
	}

	if (rte_graph_has_stats_feature()) {
		start = rte_rdtsc();
		rc = node->process(graph, node, objs, node->idx);
		node->total_cycles += rte_rdtsc() - start;
		node->total_calls++;
		node->total_objs += rc;
	} else {
		node->process(graph, node, objs, node->idx);
	}

	if (node->stream_slot_count > 0)
		__rte_node_next_stream_enqueue_flush(graph, node);

	node->idx = 0;
}

/**
 * @internal
 *
 * Enqueue a given node to the tail of the graph reel.
 *
 * @param graph
 *   Pointer Graph object.
 * @param node
 *   Pointer to node object to be enqueued.
 */
static __rte_always_inline void
__rte_node_enqueue_tail_update(struct rte_graph *graph, struct rte_node *node)
{
	uint32_t tail;

	tail = graph->tail;
	graph->cir_start[tail++] = node->off;
	graph->tail = tail & graph->cir_mask;
}

/**
 * @internal
 *
 * Enqueue sequence prologue function.
 *
 * Updates the node to tail of graph reel and resizes the number of objects
 * available in the stream as needed.
 *
 * @param graph
 *   Pointer to the graph object.
 * @param node
 *   Pointer to the node object.
 * @param idx
 *   Index at which the object enqueue starts from.
 * @param space
 *   Space required for the object enqueue.
 */
static __rte_always_inline void
__rte_node_enqueue_prologue(struct rte_graph *graph, struct rte_node *node,
			    const uint16_t idx, const uint16_t space)
{

	/* Add to the pending stream list if the node is new */
	if (idx == 0)
		__rte_node_enqueue_tail_update(graph, node);

	if (unlikely(node->size < (idx + space)))
		__rte_node_stream_alloc_size(graph, node, node->size + space);
}

/**
 * @internal
 *
 * Get the node pointer from current node edge id.
 *
 * @param node
 *   Current node pointer.
 * @param next
 *   Edge id of the required node.
 *
 * @return
 *   Pointer to the node denoted by the edge id.
 */
static __rte_always_inline struct rte_node *
__rte_node_next_node_get(struct rte_node *node, rte_edge_t next)
{
	RTE_ASSERT(next < node->nb_edges);
	RTE_ASSERT(node->fence == RTE_GRAPH_FENCE);
	node = node->nodes[next];
	RTE_ASSERT(node->fence == RTE_GRAPH_FENCE);

	return node;
}

/**
 * Enqueue the objs to next node for further processing and set
 * the next node to pending state in the circular buffer.
 *
 * @param graph
 *   Graph pointer returned from rte_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param next
 *   Relative next node index to enqueue objs.
 * @param objs
 *   Objs to enqueue.
 * @param nb_objs
 *   Number of objs to enqueue.
 */
static inline void
rte_node_enqueue(struct rte_graph *graph, struct rte_node *node,
		 rte_edge_t next, void **objs, uint16_t nb_objs)
{
	node = __rte_node_next_node_get(node, next);
	const uint16_t idx = node->idx;

	__rte_node_enqueue_prologue(graph, node, idx, nb_objs);

	rte_memcpy(&node->objs[idx], objs, nb_objs * sizeof(void *));
	node->idx = idx + nb_objs;
}

/**
 * Enqueue only one obj to next node for further processing and
 * set the next node to pending state in the circular buffer.
 *
 * @param graph
 *   Graph pointer returned from rte_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param next
 *   Relative next node index to enqueue objs.
 * @param obj
 *   Obj to enqueue.
 */
static inline void
rte_node_enqueue_x1(struct rte_graph *graph, struct rte_node *node,
		    rte_edge_t next, void *obj)
{
	node = __rte_node_next_node_get(node, next);
	uint16_t idx = node->idx;

	__rte_node_enqueue_prologue(graph, node, idx, 1);

	node->objs[idx++] = obj;
	node->idx = idx;
}

/**
 * Enqueue only two objs to next node for further processing and
 * set the next node to pending state in the circular buffer.
 * Same as rte_node_enqueue_x1 but enqueue two objs.
 *
 * @param graph
 *   Graph pointer returned from rte_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param next
 *   Relative next node index to enqueue objs.
 * @param obj0
 *   Obj to enqueue.
 * @param obj1
 *   Obj to enqueue.
 */
static inline void
rte_node_enqueue_x2(struct rte_graph *graph, struct rte_node *node,
		    rte_edge_t next, void *obj0, void *obj1)
{
	node = __rte_node_next_node_get(node, next);
	uint16_t idx = node->idx;

	__rte_node_enqueue_prologue(graph, node, idx, 2);

	node->objs[idx++] = obj0;
	node->objs[idx++] = obj1;
	node->idx = idx;
}

/**
 * Enqueue only four objs to next node for further processing and
 * set the next node to pending state in the circular buffer.
 * Same as rte_node_enqueue_x1 but enqueue four objs.
 *
 * @param graph
 *   Graph pointer returned from rte_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param next
 *   Relative next node index to enqueue objs.
 * @param obj0
 *   1st obj to enqueue.
 * @param obj1
 *   2nd obj to enqueue.
 * @param obj2
 *   3rd obj to enqueue.
 * @param obj3
 *   4th obj to enqueue.
 */
static inline void
rte_node_enqueue_x4(struct rte_graph *graph, struct rte_node *node,
		    rte_edge_t next, void *obj0, void *obj1, void *obj2,
		    void *obj3)
{
	node = __rte_node_next_node_get(node, next);
	uint16_t idx = node->idx;

	__rte_node_enqueue_prologue(graph, node, idx, 4);

	node->objs[idx++] = obj0;
	node->objs[idx++] = obj1;
	node->objs[idx++] = obj2;
	node->objs[idx++] = obj3;
	node->idx = idx;
}

/**
 * Enqueue objs to multiple next nodes for further processing and
 * set the next nodes to pending state in the circular buffer.
 * objs[i] will be enqueued to nexts[i].
 *
 * @param graph
 *   Graph pointer returned from rte_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param nexts
 *   List of relative next node indices to enqueue objs.
 * @param objs
 *   List of objs to enqueue.
 * @param nb_objs
 *   Number of objs to enqueue.
 */
static inline void
rte_node_enqueue_next(struct rte_graph *graph, struct rte_node *node,
		      rte_edge_t *nexts, void **objs, uint16_t nb_objs)
{
	uint16_t i;

	for (i = 0; i < nb_objs; i++)
		rte_node_enqueue_x1(graph, node, nexts[i], objs[i]);
}

/**
 * Get the stream of next node to enqueue the objs.
 * Once done with the updating the objs, needs to call
 * rte_node_next_stream_put to put the next node to pending state.
 *
 * @param graph
 *   Graph pointer returned from rte_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param next
 *   Relative next node index to get stream.
 * @param nb_objs
 *   Requested free size of the next stream.
 *
 * @return
 *   Valid next stream on success.
 *
 * @see rte_node_next_stream_put().
 */
static inline void **
rte_node_next_stream_get(struct rte_graph *graph, struct rte_node *node,
			 rte_edge_t next, uint16_t nb_objs)
{
	node = __rte_node_next_node_get(node, next);
	const uint16_t idx = node->idx;
	uint16_t free_space = node->size - idx;

	if (unlikely(free_space < nb_objs))
		__rte_node_stream_alloc_size(graph, node, node->size + nb_objs);

	return &node->objs[idx];
}

/**
 * Put the next stream to pending state in the circular buffer
 * for further processing. Should be invoked after rte_node_next_stream_get().
 *
 * @param graph
 *   Graph pointer returned from rte_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param next
 *   Relative next node index..
 * @param idx
 *   Number of objs updated in the stream after getting the stream using
 *   rte_node_next_stream_get.
 *
 * @see rte_node_next_stream_get().
 */
static inline void
rte_node_next_stream_put(struct rte_graph *graph, struct rte_node *node,
			 rte_edge_t next, uint16_t idx)
{
	if (unlikely(!idx))
		return;

	node = __rte_node_next_node_get(node, next);
	if (node->idx == 0)
		__rte_node_enqueue_tail_update(graph, node);

	node->idx += idx;
}

/**
 * Home run scenario, Enqueue all the objs of current node to next
 * node in optimized way by swapping the streams of both nodes.
 * Performs good when next node is already not in pending state.
 * If next node is already in pending state then normal enqueue
 * will be used.
 *
 * @param graph
 *   Graph pointer returned from rte_graph_lookup().
 * @param src
 *   Current node pointer.
 * @param next
 *   Relative next node index.
 */
static inline void
rte_node_next_stream_move(struct rte_graph *graph, struct rte_node *src,
			  rte_edge_t next)
{
	struct rte_node *dst = __rte_node_next_node_get(src, next);

	/* Let swap the pointers if dst don't have valid objs */
	if (likely(dst->idx == 0)) {
		void **dobjs = dst->objs;
		uint16_t dsz = dst->size;
		dst->objs = src->objs;
		dst->size = src->size;
		src->objs = dobjs;
		src->size = dsz;
		dst->idx = src->idx;
		__rte_node_enqueue_tail_update(graph, dst);
	} else { /* Move the objects from src node to dst node */
		rte_node_enqueue(graph, src, next, src->objs, src->idx);
	}
}

/**
 * @internal
 * Materialize slot 0: allocate destination stream and bulk copy objects
 * that were lazily accumulated in node->objs[].
 */
static inline void
__rte_node_stream_slot_materialize(struct rte_graph *graph,
				   struct rte_node *node)
{
	uint16_t n = node->stream_slots[0].count;

	node->stream_slots[0].to_next = rte_node_next_stream_get(
		graph, node, node->stream_slots[0].edge, node->idx);
	rte_memcpy(node->stream_slots[0].to_next, node->objs,
		   n * sizeof(void *));
}

/**
 * @internal
 * Find or allocate a stream slot for the given edge.
 *
 * When stream_edges are pre-declared, only those edges get slots.
 * Otherwise, slots are assigned dynamically to the first edges seen.
 * Slot 0 stays lazy (to_next == NULL) until a second slot is needed,
 * enabling rte_node_next_stream_move() at flush time.
 *
 * Returns a pointer to the slot, or NULL if no slot is available.
 */
static inline struct rte_node_stream_slot *
__rte_node_stream_slot_get(struct rte_graph *graph, struct rte_node *node,
			   rte_edge_t next)
{
	uint8_t j;

	/* Look up existing slots */
	for (j = 0; j < node->stream_slot_count; j++) {
		if (node->stream_slots[j].edge != next)
			continue;

		/* Slot 0: stay lazy until another slot is needed */
		if (j == 0)
			return &node->stream_slots[0];

		/* First use of slot j>0: materialize slot 0 and allocate */
		if (node->stream_slots[0].to_next == NULL)
			__rte_node_stream_slot_materialize(graph, node);
		if (node->stream_slots[j].to_next == NULL)
			node->stream_slots[j].to_next = rte_node_next_stream_get(
				graph, node, next, node->idx);

		return &node->stream_slots[j];
	}

	/* No matching slot: dynamic allocation if room */
	if (node->stream_slot_count >= RTE_NODE_STREAM_SLOTS_MAX)
		return NULL;

	if (node->stream_slot_count == 0) {
		/* First edge ever: lazy slot 0 */
		node->stream_slots[0].edge = next;
		node->stream_slots[0].to_next = NULL;
		node->stream_slots[0].count = 0;
		node->stream_slot_count = 1;
		return &node->stream_slots[0];
	}

	/* Materialize slot 0 if still lazy, then allocate new slot */
	if (node->stream_slots[0].to_next == NULL)
		__rte_node_stream_slot_materialize(graph, node);

	j = node->stream_slot_count++;
	node->stream_slots[j].edge = next;
	node->stream_slots[j].to_next = rte_node_next_stream_get(
		graph, node, next, node->idx);
	node->stream_slots[j].count = 0;
	return &node->stream_slots[j];
}

/**
 * Enqueue a batch of objects to a single next edge.
 *
 * Uses a small cache of destination streams (up to RTE_NODE_STREAM_SLOTS_MAX
 * edges). Objects are written directly into the destination node's stream,
 * keeping it cache-hot.
 *
 * The first edge used (slot 0) is handled lazily: objects stay in
 * node->objs[] without any copy. If all objects go to the same edge,
 * rte_node_next_stream_move() is used at flush time (zero copy pointer
 * swap). When a second edge is encountered, slot 0 is materialized (bulk
 * copied to the destination stream) and subsequent writes go directly into
 * destination streams.
 *
 * Preferred edges can be declared in the node registration
 * (stream_edges[]) or updated at runtime with
 * rte_node_stream_edges_update(). When no edges are declared, slots are
 * assigned dynamically as new edges appear.
 *
 * @param graph
 *   Graph pointer returned from rte_graph_lookup().
 * @param node
 *   Current node pointer.
 * @param next
 *   Next node edge index to enqueue to.
 * @param objs
 *   Array of object pointers to enqueue.
 * @param nb_objs
 *   Number of objects.
 *
 * @see rte_node_next_stream_move().
 * @see rte_node_stream_edges_update().
 */
static inline void
rte_node_next_stream_enqueue(struct rte_graph *graph, struct rte_node *node,
			     rte_edge_t next, void **objs, uint16_t nb_objs)
{
	struct rte_node_stream_slot *slot;

	slot = __rte_node_stream_slot_get(graph, node, next);
	if (likely(slot != NULL)) {
		if (slot->to_next != NULL)
			rte_memcpy(&slot->to_next[slot->count],
				   objs, nb_objs * sizeof(void *));
		slot->count += nb_objs;
	} else {
		rte_node_enqueue(graph, node, next, objs, nb_objs);
	}
}

/**
 * Enqueue one object to a next edge.
 *
 * @see rte_node_next_stream_enqueue().
 */
static inline void
rte_node_next_stream_enqueue_x1(struct rte_graph *graph, struct rte_node *node,
				rte_edge_t next, void *obj)
{
	struct rte_node_stream_slot *slot;

	slot = __rte_node_stream_slot_get(graph, node, next);
	if (likely(slot != NULL)) {
		if (slot->to_next != NULL)
			slot->to_next[slot->count] = obj;
		slot->count++;
	} else {
		rte_node_enqueue_x1(graph, node, next, obj);
	}
}

/**
 * Enqueue 2 objects to next edges (possibly different).
 *
 * @see rte_node_next_stream_enqueue().
 */
static inline void
rte_node_next_stream_enqueue_x2(struct rte_graph *graph, struct rte_node *node,
				rte_edge_t next0, void *obj0,
				rte_edge_t next1, void *obj1)
{
	if (likely(next0 == next1)) {
		void *objs[2] = { obj0, obj1 };

		rte_node_next_stream_enqueue(graph, node, next0, objs, 2);
	} else {
		rte_node_next_stream_enqueue_x1(graph, node, next0, obj0);
		rte_node_next_stream_enqueue_x1(graph, node, next1, obj1);
	}
}

/**
 * Enqueue 4 objects to next edges (possibly different).
 *
 * When all 4 edges are identical (common case), a single slot lookup is
 * done. Otherwise falls back to per-object enqueue.
 *
 * @see rte_node_next_stream_enqueue().
 */
static inline void
rte_node_next_stream_enqueue_x4(struct rte_graph *graph, struct rte_node *node,
				rte_edge_t next0, void *obj0,
				rte_edge_t next1, void *obj1,
				rte_edge_t next2, void *obj2,
				rte_edge_t next3, void *obj3)
{
	if (likely(!((next0 ^ next1) | (next1 ^ next2) | (next2 ^ next3)))) {
		void *objs[4] = { obj0, obj1, obj2, obj3 };

		rte_node_next_stream_enqueue(graph, node, next0, objs, 4);
	} else {
		rte_node_next_stream_enqueue_x1(graph, node, next0, obj0);
		rte_node_next_stream_enqueue_x1(graph, node, next1, obj1);
		rte_node_next_stream_enqueue_x1(graph, node, next2, obj2);
		rte_node_next_stream_enqueue_x1(graph, node, next3, obj3);
	}
}

/**
 * @internal
 * Flush stream enqueue slots at end of node processing.
 */
static inline void
__rte_node_next_stream_enqueue_flush(struct rte_graph *graph, struct rte_node *node)
{
	uint8_t j;

	/*
	 * If slot 0 is still lazy, no other slot can have data (because
	 * materializing slot 0 is a prerequisite to using any other slot).
	 */
	if (node->stream_slots[0].to_next == NULL) {
		if (node->stream_slots[0].count == 0)
			return;
		/*
		 * stream_move transfers node->idx objects. Only safe when
		 * all objects were enqueued to slot 0.
		 */
		if (node->stream_slots[0].count == node->idx) {
			rte_node_next_stream_move(graph, node,
						  node->stream_slots[0].edge);
			return;
		}
		/* Partial enqueue: materialize and use stream_put */
		__rte_node_stream_slot_materialize(graph, node);
		rte_node_next_stream_put(graph, node,
					 node->stream_slots[0].edge,
					 node->stream_slots[0].count);
		return;
	}

	for (j = 0; j < node->stream_slot_count; j++) {
		if (node->stream_slots[j].count > 0)
			rte_node_next_stream_put(graph, node,
						 node->stream_slots[j].edge,
						 node->stream_slots[j].count);
	}
}

/**
 * Test the validity of model.
 *
 * @param model
 *   Model to check.
 *
 * @return
 *   True if graph model is valid, false otherwise.
 */
bool
rte_graph_model_is_valid(uint8_t model);

/**
 * @note This function does not perform any locking, and is only safe to call
 *    before graph running. It will set all graphs the same model.
 *
 * @param model
 *   Name of the graph worker model.
 *
 * @return
 *   0 on success, -1 otherwise.
 */
int rte_graph_worker_model_set(uint8_t model);

/**
 * Get the graph worker model
 *
 * @note All graph will use the same model and this function will get model from the first one.
 *    Used for slow path.
 *
 * @param graph
 *   Graph pointer.
 *
 * @return
 *   Graph worker model on success.
 */
uint8_t rte_graph_worker_model_get(struct rte_graph *graph);

/**
 * Get the graph worker model without check
 *
 * @note All graph will use the same model and this function will get model from the first one.
 *    Used for fast path.
 *
 * @param graph
 *   Graph pointer.
 *
 * @return
 *   Graph worker model on success.
 */
static __rte_always_inline
uint8_t rte_graph_worker_model_no_check_get(struct rte_graph *graph)
{
	return graph->model;
}

/**
 * Increment Node xstat count.
 *
 * Increment the count of an xstat for a given node.
 *
 * @param node
 *   Pointer to the node.
 * @param xstat_id
 *   xstat ID.
 * @param value
 *   Value to increment.
 */
__rte_experimental
static inline void
rte_node_xstat_increment(struct rte_node *node, uint16_t xstat_id, uint64_t value)
{
	if (rte_graph_has_stats_feature()) {
		uint64_t *xstat = (uint64_t *)RTE_PTR_ADD(node, node->xstat_off);
		xstat[xstat_id] += value;
	}
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_GRAPH_WORKER_COIMMON_H_ */
