/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Corigine, Inc.
 * All rights reserved.
 */

#include <rte_flow_driver.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <bus_pci_driver.h>
#include <rte_malloc.h>

#include "nfp_common.h"
#include "nfp_flow.h"
#include "nfp_logs.h"
#include "flower/nfp_flower.h"
#include "flower/nfp_flower_cmsg.h"
#include "flower/nfp_flower_ctrl.h"
#include "flower/nfp_flower_representor.h"
#include "nfpcore/nfp_mip.h"
#include "nfpcore/nfp_rtsym.h"

/* Static initializer for a list of subsequent item types */
#define NEXT_ITEM(...) \
	((const enum rte_flow_item_type []){ \
		__VA_ARGS__, RTE_FLOW_ITEM_TYPE_END, \
	})

/* Process structure associated with a flow item */
struct nfp_flow_item_proc {
	/* Bit-mask for fields supported by this PMD. */
	const void *mask_support;
	/* Bit-mask to use when @p item->mask is not provided. */
	const void *mask_default;
	/* Size in bytes for @p mask_support and @p mask_default. */
	const unsigned int mask_sz;
	/* Merge a pattern item into a flow rule handle. */
	int (*merge)(struct rte_flow *nfp_flow,
			char **mbuf_off,
			const struct rte_flow_item *item,
			const struct nfp_flow_item_proc *proc,
			bool is_mask);
	/* List of possible subsequent items. */
	const enum rte_flow_item_type *const next_item;
};

struct nfp_mask_id_entry {
	uint32_t hash_key;
	uint32_t ref_cnt;
	uint8_t mask_id;
};

static inline struct nfp_flow_priv *
nfp_flow_dev_to_priv(struct rte_eth_dev *dev)
{
	struct nfp_flower_representor *repr;

	repr = (struct nfp_flower_representor *)dev->data->dev_private;
	return repr->app_fw_flower->flow_priv;
}

static int
nfp_mask_id_alloc(struct nfp_flow_priv *priv, uint8_t *mask_id)
{
	uint8_t temp_id;
	uint8_t freed_id;
	struct circ_buf *ring;

	/* Checking for unallocated entries first. */
	if (priv->mask_ids.init_unallocated > 0) {
		*mask_id = priv->mask_ids.init_unallocated;
		priv->mask_ids.init_unallocated--;
		return 0;
	}

	/* Checking if buffer is empty. */
	freed_id = NFP_FLOWER_MASK_ENTRY_RS - 1;
	ring = &priv->mask_ids.free_list;
	if (ring->head == ring->tail) {
		*mask_id = freed_id;
		return -ENOENT;
	}

	rte_memcpy(&temp_id, &ring->buf[ring->tail], NFP_FLOWER_MASK_ELEMENT_RS);
	*mask_id = temp_id;

	rte_memcpy(&ring->buf[ring->tail], &freed_id, NFP_FLOWER_MASK_ELEMENT_RS);
	ring->tail = (ring->tail + NFP_FLOWER_MASK_ELEMENT_RS) %
			(NFP_FLOWER_MASK_ENTRY_RS * NFP_FLOWER_MASK_ELEMENT_RS);

	return 0;
}

static int
nfp_mask_id_free(struct nfp_flow_priv *priv, uint8_t mask_id)
{
	struct circ_buf *ring;

	ring = &priv->mask_ids.free_list;

	/* Checking if buffer is full. */
	if (CIRC_SPACE(ring->head, ring->tail, NFP_FLOWER_MASK_ENTRY_RS) == 0)
		return -ENOBUFS;

	rte_memcpy(&ring->buf[ring->head], &mask_id, NFP_FLOWER_MASK_ELEMENT_RS);
	ring->head = (ring->head + NFP_FLOWER_MASK_ELEMENT_RS) %
			(NFP_FLOWER_MASK_ENTRY_RS * NFP_FLOWER_MASK_ELEMENT_RS);

	return 0;
}

static int
nfp_mask_table_add(struct nfp_flow_priv *priv,
		char *mask_data,
		uint32_t mask_len,
		uint8_t *id)
{
	int ret;
	uint8_t mask_id;
	uint32_t hash_key;
	struct nfp_mask_id_entry *mask_entry;

	mask_entry = rte_zmalloc("mask_entry", sizeof(struct nfp_mask_id_entry), 0);
	if (mask_entry == NULL) {
		ret = -ENOMEM;
		goto exit;
	}

	ret = nfp_mask_id_alloc(priv, &mask_id);
	if (ret != 0)
		goto mask_entry_free;

	hash_key = rte_jhash(mask_data, mask_len, priv->hash_seed);
	mask_entry->mask_id  = mask_id;
	mask_entry->hash_key = hash_key;
	mask_entry->ref_cnt  = 1;
	PMD_DRV_LOG(DEBUG, "hash_key=%#x id=%u ref=%u", hash_key,
			mask_id, mask_entry->ref_cnt);

	ret = rte_hash_add_key_data(priv->mask_table, &hash_key, mask_entry);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Add to mask table failed.");
		goto mask_id_free;
	}

	*id = mask_id;
	return 0;

mask_id_free:
	nfp_mask_id_free(priv, mask_id);
mask_entry_free:
	rte_free(mask_entry);
exit:
	return ret;
}

static int
nfp_mask_table_del(struct nfp_flow_priv *priv,
		char *mask_data,
		uint32_t mask_len,
		uint8_t id)
{
	int ret;
	uint32_t hash_key;

	hash_key = rte_jhash(mask_data, mask_len, priv->hash_seed);
	ret = rte_hash_del_key(priv->mask_table, &hash_key);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "Delete from mask table failed.");
		return ret;
	}

	ret = nfp_mask_id_free(priv, id);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Free mask id failed.");
		return ret;
	}

	return 0;
}

static struct nfp_mask_id_entry *
nfp_mask_table_search(struct nfp_flow_priv *priv,
		char *mask_data,
		uint32_t mask_len)
{
	int index;
	uint32_t hash_key;
	struct nfp_mask_id_entry *entry;

	hash_key = rte_jhash(mask_data, mask_len, priv->hash_seed);
	index = rte_hash_lookup_data(priv->mask_table, &hash_key, (void **)&entry);
	if (index < 0) {
		PMD_DRV_LOG(DEBUG, "Data NOT found in the mask table.");
		return NULL;
	}

	return entry;
}

static bool
nfp_check_mask_add(struct nfp_flow_priv *priv,
		char *mask_data,
		uint32_t mask_len,
		uint8_t *meta_flags,
		uint8_t *mask_id)
{
	int ret;
	struct nfp_mask_id_entry *mask_entry;

	mask_entry = nfp_mask_table_search(priv, mask_data, mask_len);
	if (mask_entry == NULL) {
		/* mask entry does not exist, let's create one */
		ret = nfp_mask_table_add(priv, mask_data, mask_len, mask_id);
		if (ret != 0)
			return false;

		*meta_flags |= NFP_FL_META_FLAG_MANAGE_MASK;
	} else {
		/* mask entry already exist */
		mask_entry->ref_cnt++;
		*mask_id = mask_entry->mask_id;
	}

	return true;
}

static bool
nfp_check_mask_remove(struct nfp_flow_priv *priv,
		char *mask_data,
		uint32_t mask_len,
		uint8_t *meta_flags)
{
	int ret;
	struct nfp_mask_id_entry *mask_entry;

	mask_entry = nfp_mask_table_search(priv, mask_data, mask_len);
	if (mask_entry == NULL)
		return false;

	mask_entry->ref_cnt--;
	if (mask_entry->ref_cnt == 0) {
		ret = nfp_mask_table_del(priv, mask_data, mask_len,
				mask_entry->mask_id);
		if (ret != 0)
			return false;

		rte_free(mask_entry);
		if (meta_flags)
			*meta_flags &= ~NFP_FL_META_FLAG_MANAGE_MASK;
	}

	return true;
}

static int
nfp_flow_table_add(struct nfp_flow_priv *priv,
		struct rte_flow *nfp_flow)
{
	int ret;

	ret = rte_hash_add_key_data(priv->flow_table, &nfp_flow->hash_key, nfp_flow);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Add to flow table failed.");
		return ret;
	}

	return 0;
}

static int
nfp_flow_table_delete(struct nfp_flow_priv *priv,
		struct rte_flow *nfp_flow)
{
	int ret;

	ret = rte_hash_del_key(priv->flow_table, &nfp_flow->hash_key);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "Delete from flow table failed.");
		return ret;
	}

	return 0;
}

static struct rte_flow *
nfp_flow_table_search(struct nfp_flow_priv *priv,
		struct rte_flow *nfp_flow)
{
	int index;
	struct rte_flow *flow_find;

	index = rte_hash_lookup_data(priv->flow_table, &nfp_flow->hash_key,
			(void **)&flow_find);
	if (index < 0) {
		PMD_DRV_LOG(DEBUG, "Data NOT found in the flow table.");
		return NULL;
	}

	return flow_find;
}

static struct rte_flow *
nfp_flow_alloc(struct nfp_fl_key_ls *key_layer)
{
	char *tmp;
	size_t len;
	struct rte_flow *nfp_flow;
	struct nfp_fl_payload *payload;

	nfp_flow = rte_zmalloc("nfp_flow", sizeof(struct rte_flow), 0);
	if (nfp_flow == NULL)
		goto exit;

	len = key_layer->key_size + key_layer->key_size + key_layer->act_size;
	tmp = rte_zmalloc("nfp_flow_payload", len + sizeof(struct nfp_fl_rule_metadata), 0);
	if (tmp == NULL)
		goto free_flow;

	nfp_flow->length = len;

	payload                = &nfp_flow->payload;
	payload->meta          = (struct nfp_fl_rule_metadata *)tmp;
	payload->unmasked_data = tmp + sizeof(struct nfp_fl_rule_metadata);
	payload->mask_data     = payload->unmasked_data + key_layer->key_size;
	payload->action_data   = payload->mask_data + key_layer->key_size;

	return nfp_flow;

free_flow:
	rte_free(nfp_flow);
exit:
	return NULL;
}

static void
nfp_flow_free(struct rte_flow *nfp_flow)
{
	rte_free(nfp_flow->payload.meta);
	rte_free(nfp_flow);
}

static int
nfp_stats_id_alloc(struct nfp_flow_priv *priv, uint32_t *ctx)
{
	struct circ_buf *ring;
	uint32_t temp_stats_id;
	uint32_t freed_stats_id;

	/* Check for unallocated entries first. */
	if (priv->stats_ids.init_unallocated > 0) {
		*ctx = ((priv->stats_ids.init_unallocated - 1) & NFP_FL_STAT_ID_STAT) |
				(priv->active_mem_unit & NFP_FL_STAT_ID_MU_NUM);
		if (++priv->active_mem_unit == priv->total_mem_units) {
			priv->stats_ids.init_unallocated--;
			priv->active_mem_unit = 0;
		}
		return 0;
	}

	/* Check if buffer is empty */
	ring = &priv->stats_ids.free_list;
	freed_stats_id = priv->stats_ring_size;
	if (ring->head == ring->tail) {
		*ctx = freed_stats_id;
		return -ENOENT;
	}

	memcpy(&temp_stats_id, &ring->buf[ring->tail], NFP_FL_STATS_ELEM_RS);
	*ctx = temp_stats_id;
	memcpy(&ring->buf[ring->tail], &freed_stats_id, NFP_FL_STATS_ELEM_RS);
	ring->tail = (ring->tail + NFP_FL_STATS_ELEM_RS) %
			(priv->stats_ring_size * NFP_FL_STATS_ELEM_RS);

	return 0;
}

static int
nfp_stats_id_free(struct nfp_flow_priv *priv, uint32_t ctx)
{
	struct circ_buf *ring;

	/* Check if buffer is full */
	ring = &priv->stats_ids.free_list;
	if (!CIRC_SPACE(ring->head, ring->tail, priv->stats_ring_size *
			NFP_FL_STATS_ELEM_RS - NFP_FL_STATS_ELEM_RS + 1))
		return -ENOBUFS;

	memcpy(&ring->buf[ring->head], &ctx, NFP_FL_STATS_ELEM_RS);
	ring->head = (ring->head + NFP_FL_STATS_ELEM_RS) %
			(priv->stats_ring_size * NFP_FL_STATS_ELEM_RS);

	return 0;
}

static void
nfp_flower_compile_meta_tci(char *mbuf_off, struct nfp_fl_key_ls *key_layer)
{
	struct nfp_flower_meta_tci *tci_meta;

	tci_meta = (struct nfp_flower_meta_tci *)mbuf_off;
	tci_meta->nfp_flow_key_layer = key_layer->key_layer;
	tci_meta->mask_id = ~0;
	tci_meta->tci = rte_cpu_to_be_16(key_layer->vlan);
}

static void
nfp_flower_update_meta_tci(char *exact, uint8_t mask_id)
{
	struct nfp_flower_meta_tci *meta_tci;

	meta_tci = (struct nfp_flower_meta_tci *)exact;
	meta_tci->mask_id = mask_id;
}

static void
nfp_flower_compile_ext_meta(char *mbuf_off, struct nfp_fl_key_ls *key_layer)
{
	struct nfp_flower_ext_meta *ext_meta;

	ext_meta = (struct nfp_flower_ext_meta *)mbuf_off;
	ext_meta->nfp_flow_key_layer2 = rte_cpu_to_be_32(key_layer->key_layer_two);
}

static void
nfp_compile_meta_port(char *mbuf_off,
		struct nfp_fl_key_ls *key_layer,
		bool is_mask)
{
	struct nfp_flower_in_port *port_meta;

	port_meta = (struct nfp_flower_in_port *)mbuf_off;

	if (is_mask)
		port_meta->in_port = rte_cpu_to_be_32(~0);
	else if (key_layer->tun_type)
		port_meta->in_port = rte_cpu_to_be_32(NFP_FL_PORT_TYPE_TUN |
				key_layer->tun_type);
	else
		port_meta->in_port = rte_cpu_to_be_32(key_layer->port);
}

static void
nfp_flow_compile_metadata(struct nfp_flow_priv *priv,
		struct rte_flow *nfp_flow,
		struct nfp_fl_key_ls *key_layer,
		uint32_t stats_ctx)
{
	struct nfp_fl_rule_metadata *nfp_flow_meta;
	char *mbuf_off_exact;
	char *mbuf_off_mask;

	/*
	 * Convert to long words as firmware expects
	 * lengths in units of NFP_FL_LW_SIZ.
	 */
	nfp_flow_meta               = nfp_flow->payload.meta;
	nfp_flow_meta->key_len      = key_layer->key_size >> NFP_FL_LW_SIZ;
	nfp_flow_meta->mask_len     = key_layer->key_size >> NFP_FL_LW_SIZ;
	nfp_flow_meta->act_len      = key_layer->act_size >> NFP_FL_LW_SIZ;
	nfp_flow_meta->flags        = 0;
	nfp_flow_meta->host_ctx_id  = rte_cpu_to_be_32(stats_ctx);
	nfp_flow_meta->host_cookie  = rte_rand();
	nfp_flow_meta->flow_version = rte_cpu_to_be_64(priv->flower_version);

	mbuf_off_exact = nfp_flow->payload.unmasked_data;
	mbuf_off_mask  = nfp_flow->payload.mask_data;

	/* Populate Metadata */
	nfp_flower_compile_meta_tci(mbuf_off_exact, key_layer);
	nfp_flower_compile_meta_tci(mbuf_off_mask, key_layer);
	mbuf_off_exact += sizeof(struct nfp_flower_meta_tci);
	mbuf_off_mask  += sizeof(struct nfp_flower_meta_tci);

	/* Populate Extended Metadata if required */
	if (key_layer->key_layer & NFP_FLOWER_LAYER_EXT_META) {
		nfp_flower_compile_ext_meta(mbuf_off_exact, key_layer);
		nfp_flower_compile_ext_meta(mbuf_off_mask, key_layer);
		mbuf_off_exact += sizeof(struct nfp_flower_ext_meta);
		mbuf_off_mask  += sizeof(struct nfp_flower_ext_meta);
	}

	/* Populate Port Data */
	nfp_compile_meta_port(mbuf_off_exact, key_layer, false);
	nfp_compile_meta_port(mbuf_off_mask, key_layer, true);
	mbuf_off_exact += sizeof(struct nfp_flower_in_port);
	mbuf_off_mask  += sizeof(struct nfp_flower_in_port);
}

static int
nfp_flow_key_layers_calculate_items(const struct rte_flow_item items[],
		struct nfp_fl_key_ls *key_ls)
{
	struct rte_eth_dev *ethdev;
	const struct rte_flow_item *item;
	struct nfp_flower_representor *representor;
	const struct rte_flow_item_port_id *port_id;

	for (item = items; item->type != RTE_FLOW_ITEM_TYPE_END; ++item) {
		switch (item->type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			PMD_DRV_LOG(DEBUG, "RTE_FLOW_ITEM_TYPE_ETH detected");
			/*
			 * eth is set with no specific params.
			 * NFP does not need this.
			 */
			if (item->spec == NULL)
				continue;
			key_ls->key_layer |= NFP_FLOWER_LAYER_MAC;
			key_ls->key_size += sizeof(struct nfp_flower_mac_mpls);
			break;
		case RTE_FLOW_ITEM_TYPE_PORT_ID:
			PMD_DRV_LOG(DEBUG, "RTE_FLOW_ITEM_TYPE_PORT_ID detected");
			port_id = item->spec;
			if (port_id->id >= RTE_MAX_ETHPORTS)
				return -ERANGE;
			ethdev = &rte_eth_devices[port_id->id];
			representor = (struct nfp_flower_representor *)
					ethdev->data->dev_private;
			key_ls->port = rte_cpu_to_be_32(representor->port_id);
			break;
		case RTE_FLOW_ITEM_TYPE_VLAN:
			PMD_DRV_LOG(DEBUG, "RTE_FLOW_ITEM_TYPE_VLAN detected");
			key_ls->vlan = NFP_FLOWER_MASK_VLAN_CFI;
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			PMD_DRV_LOG(DEBUG, "RTE_FLOW_ITEM_TYPE_IPV4 detected");
			key_ls->key_layer |= NFP_FLOWER_LAYER_IPV4;
			key_ls->key_size += sizeof(struct nfp_flower_ipv4);
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			PMD_DRV_LOG(DEBUG, "RTE_FLOW_ITEM_TYPE_IPV6 detected");
			key_ls->key_layer |= NFP_FLOWER_LAYER_IPV6;
			key_ls->key_size += sizeof(struct nfp_flower_ipv6);
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			PMD_DRV_LOG(DEBUG, "RTE_FLOW_ITEM_TYPE_TCP detected");
			key_ls->key_layer |= NFP_FLOWER_LAYER_TP;
			key_ls->key_size += sizeof(struct nfp_flower_tp_ports);
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			PMD_DRV_LOG(DEBUG, "RTE_FLOW_ITEM_TYPE_UDP detected");
			key_ls->key_layer |= NFP_FLOWER_LAYER_TP;
			key_ls->key_size += sizeof(struct nfp_flower_tp_ports);
			break;
		case RTE_FLOW_ITEM_TYPE_SCTP:
			PMD_DRV_LOG(DEBUG, "RTE_FLOW_ITEM_TYPE_SCTP detected");
			key_ls->key_layer |= NFP_FLOWER_LAYER_TP;
			key_ls->key_size += sizeof(struct nfp_flower_tp_ports);
			break;
		default:
			PMD_DRV_LOG(ERR, "Item type %d not supported.", item->type);
			return -ENOTSUP;
		}
	}

	return 0;
}

static int
nfp_flow_key_layers_calculate_actions(const struct rte_flow_action actions[],
		struct nfp_fl_key_ls *key_ls)
{
	int ret = 0;
	bool mac_set_flag = false;
	const struct rte_flow_action *action;

	for (action = actions; action->type != RTE_FLOW_ACTION_TYPE_END; ++action) {
		/* Make sure actions length no longer than NFP_FL_MAX_A_SIZ */
		if (key_ls->act_size > NFP_FL_MAX_A_SIZ) {
			PMD_DRV_LOG(ERR, "The action list is too long.");
			ret = -ERANGE;
			break;
		}

		switch (action->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			PMD_DRV_LOG(DEBUG, "RTE_FLOW_ACTION_TYPE_VOID detected");
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			PMD_DRV_LOG(DEBUG, "RTE_FLOW_ACTION_TYPE_DROP detected");
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			PMD_DRV_LOG(DEBUG, "RTE_FLOW_ACTION_TYPE_COUNT detected");
			break;
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
			PMD_DRV_LOG(DEBUG, "RTE_FLOW_ACTION_TYPE_PORT_ID detected");
			key_ls->act_size += sizeof(struct nfp_fl_act_output);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_MAC_SRC:
			PMD_DRV_LOG(DEBUG, "RTE_FLOW_ACTION_TYPE_SET_MAC_SRC detected");
			if (!mac_set_flag) {
				key_ls->act_size += sizeof(struct nfp_fl_act_set_eth);
				mac_set_flag = true;
			}
			break;
		default:
			PMD_DRV_LOG(ERR, "Action type %d not supported.", action->type);
			return -ENOTSUP;
		}
	}

	return ret;
}

static int
nfp_flow_key_layers_calculate(const struct rte_flow_item items[],
		const struct rte_flow_action actions[],
		struct nfp_fl_key_ls *key_ls)
{
	int ret = 0;

	key_ls->key_layer_two = 0;
	key_ls->key_layer = NFP_FLOWER_LAYER_PORT;
	key_ls->key_size = sizeof(struct nfp_flower_meta_tci) +
			sizeof(struct nfp_flower_in_port);
	key_ls->act_size = 0;
	key_ls->port = ~0;
	key_ls->vlan = 0;
	key_ls->tun_type = NFP_FL_TUN_NONE;

	ret |= nfp_flow_key_layers_calculate_items(items, key_ls);
	ret |= nfp_flow_key_layers_calculate_actions(actions, key_ls);

	return ret;
}

static int
nfp_flow_merge_eth(__rte_unused struct rte_flow *nfp_flow,
		char **mbuf_off,
		const struct rte_flow_item *item,
		const struct nfp_flow_item_proc *proc,
		bool is_mask)
{
	struct nfp_flower_mac_mpls *eth;
	const struct rte_flow_item_eth *spec;
	const struct rte_flow_item_eth *mask;

	spec = item->spec;
	if (spec == NULL) {
		PMD_DRV_LOG(DEBUG, "nfp flow merge eth: no item->spec!");
		goto eth_end;
	}

	mask = item->mask ? item->mask : proc->mask_default;
	eth = (void *)*mbuf_off;

	if (is_mask) {
		memcpy(eth->mac_src, mask->src.addr_bytes, RTE_ETHER_ADDR_LEN);
		memcpy(eth->mac_dst, mask->dst.addr_bytes, RTE_ETHER_ADDR_LEN);
	} else {
		memcpy(eth->mac_src, spec->src.addr_bytes, RTE_ETHER_ADDR_LEN);
		memcpy(eth->mac_dst, spec->dst.addr_bytes, RTE_ETHER_ADDR_LEN);
	}

	eth->mpls_lse = 0;

eth_end:
	*mbuf_off += sizeof(struct nfp_flower_mac_mpls);

	return 0;
}

static int
nfp_flow_merge_vlan(struct rte_flow *nfp_flow,
		__rte_unused char **mbuf_off,
		const struct rte_flow_item *item,
		const struct nfp_flow_item_proc *proc,
		bool is_mask)
{
	struct nfp_flower_meta_tci *meta_tci;
	const struct rte_flow_item_vlan *spec;
	const struct rte_flow_item_vlan *mask;

	spec = item->spec;
	if (spec == NULL) {
		PMD_DRV_LOG(DEBUG, "nfp flow merge vlan: no item->spec!");
		return 0;
	}

	mask = item->mask ? item->mask : proc->mask_default;
	if (is_mask) {
		meta_tci = (struct nfp_flower_meta_tci *)nfp_flow->payload.mask_data;
		meta_tci->tci |= mask->tci;
	} else {
		meta_tci = (struct nfp_flower_meta_tci *)nfp_flow->payload.unmasked_data;
		meta_tci->tci |= spec->tci;
	}

	return 0;
}

static int
nfp_flow_merge_ipv4(struct rte_flow *nfp_flow,
		char **mbuf_off,
		const struct rte_flow_item *item,
		const struct nfp_flow_item_proc *proc,
		bool is_mask)
{
	struct nfp_flower_ipv4 *ipv4;
	const struct rte_ipv4_hdr *hdr;
	struct nfp_flower_meta_tci *meta_tci;
	const struct rte_flow_item_ipv4 *spec;
	const struct rte_flow_item_ipv4 *mask;

	spec = item->spec;
	mask = item->mask ? item->mask : proc->mask_default;
	meta_tci = (struct nfp_flower_meta_tci *)nfp_flow->payload.unmasked_data;

	if (spec == NULL) {
		PMD_DRV_LOG(DEBUG, "nfp flow merge ipv4: no item->spec!");
		goto ipv4_end;
	}

	/*
	 * reserve space for L4 info.
	 * rte_flow has ipv4 before L4 but NFP flower fw requires L4 before ipv4
	 */
	if (meta_tci->nfp_flow_key_layer & NFP_FLOWER_LAYER_TP)
		*mbuf_off += sizeof(struct nfp_flower_tp_ports);

	hdr = is_mask ? &mask->hdr : &spec->hdr;
	ipv4 = (struct nfp_flower_ipv4 *)*mbuf_off;

	ipv4->ip_ext.tos   = hdr->type_of_service;
	ipv4->ip_ext.proto = hdr->next_proto_id;
	ipv4->ip_ext.ttl   = hdr->time_to_live;
	ipv4->ipv4_src     = hdr->src_addr;
	ipv4->ipv4_dst     = hdr->dst_addr;

ipv4_end:
	*mbuf_off += sizeof(struct nfp_flower_ipv4);

	return 0;
}

static int
nfp_flow_merge_ipv6(struct rte_flow *nfp_flow,
		char **mbuf_off,
		const struct rte_flow_item *item,
		const struct nfp_flow_item_proc *proc,
		bool is_mask)
{
	struct nfp_flower_ipv6 *ipv6;
	const struct rte_ipv6_hdr *hdr;
	struct nfp_flower_meta_tci *meta_tci;
	const struct rte_flow_item_ipv6 *spec;
	const struct rte_flow_item_ipv6 *mask;

	spec = item->spec;
	mask = item->mask ? item->mask : proc->mask_default;
	meta_tci = (struct nfp_flower_meta_tci *)nfp_flow->payload.unmasked_data;

	if (spec == NULL) {
		PMD_DRV_LOG(DEBUG, "nfp flow merge ipv6: no item->spec!");
		goto ipv6_end;
	}

	/*
	 * reserve space for L4 info.
	 * rte_flow has ipv4 before L4 but NFP flower fw requires L4 before ipv4
	 */
	if (meta_tci->nfp_flow_key_layer & NFP_FLOWER_LAYER_TP)
		*mbuf_off += sizeof(struct nfp_flower_tp_ports);

	hdr = is_mask ? &mask->hdr : &spec->hdr;
	ipv6 = (struct nfp_flower_ipv6 *)*mbuf_off;

	ipv6->ip_ext.tos   = (hdr->vtc_flow & RTE_IPV6_HDR_TC_MASK) >>
			RTE_IPV6_HDR_TC_SHIFT;
	ipv6->ip_ext.proto = hdr->proto;
	ipv6->ip_ext.ttl   = hdr->hop_limits;
	memcpy(ipv6->ipv6_src, hdr->src_addr, sizeof(ipv6->ipv6_src));
	memcpy(ipv6->ipv6_dst, hdr->dst_addr, sizeof(ipv6->ipv6_dst));

ipv6_end:
	*mbuf_off += sizeof(struct nfp_flower_ipv6);

	return 0;
}

static int
nfp_flow_merge_tcp(struct rte_flow *nfp_flow,
		char **mbuf_off,
		const struct rte_flow_item *item,
		const struct nfp_flow_item_proc *proc,
		bool is_mask)
{
	uint8_t tcp_flags;
	struct nfp_flower_tp_ports *ports;
	struct nfp_flower_ipv4 *ipv4 = NULL;
	struct nfp_flower_ipv6 *ipv6 = NULL;
	const struct rte_flow_item_tcp *spec;
	const struct rte_flow_item_tcp *mask;
	struct nfp_flower_meta_tci *meta_tci;

	spec = item->spec;
	if (spec == NULL) {
		PMD_DRV_LOG(DEBUG, "nfp flow merge tcp: no item->spec!");
		return 0;
	}

	meta_tci = (struct nfp_flower_meta_tci *)nfp_flow->payload.unmasked_data;
	if (meta_tci->nfp_flow_key_layer & NFP_FLOWER_LAYER_IPV4) {
		ipv4  = (struct nfp_flower_ipv4 *)
			(*mbuf_off - sizeof(struct nfp_flower_ipv4));
		ports = (struct nfp_flower_tp_ports *)
			((char *)ipv4 - sizeof(struct nfp_flower_tp_ports));
	} else { /* IPv6 */
		ipv6  = (struct nfp_flower_ipv6 *)
			(*mbuf_off - sizeof(struct nfp_flower_ipv6));
		ports = (struct nfp_flower_tp_ports *)
			((char *)ipv6 - sizeof(struct nfp_flower_tp_ports));
	}

	mask = item->mask ? item->mask : proc->mask_default;
	if (is_mask) {
		ports->port_src = mask->hdr.src_port;
		ports->port_dst = mask->hdr.dst_port;
		tcp_flags       = mask->hdr.tcp_flags;
	} else {
		ports->port_src = spec->hdr.src_port;
		ports->port_dst = spec->hdr.dst_port;
		tcp_flags       = spec->hdr.tcp_flags;
	}

	if (ipv4) {
		if (tcp_flags & RTE_TCP_FIN_FLAG)
			ipv4->ip_ext.flags |= NFP_FL_TCP_FLAG_FIN;
		if (tcp_flags & RTE_TCP_SYN_FLAG)
			ipv4->ip_ext.flags |= NFP_FL_TCP_FLAG_SYN;
		if (tcp_flags & RTE_TCP_RST_FLAG)
			ipv4->ip_ext.flags |= NFP_FL_TCP_FLAG_RST;
		if (tcp_flags & RTE_TCP_PSH_FLAG)
			ipv4->ip_ext.flags |= NFP_FL_TCP_FLAG_PSH;
		if (tcp_flags & RTE_TCP_URG_FLAG)
			ipv4->ip_ext.flags |= NFP_FL_TCP_FLAG_URG;
	} else {  /* IPv6 */
		if (tcp_flags & RTE_TCP_FIN_FLAG)
			ipv6->ip_ext.flags |= NFP_FL_TCP_FLAG_FIN;
		if (tcp_flags & RTE_TCP_SYN_FLAG)
			ipv6->ip_ext.flags |= NFP_FL_TCP_FLAG_SYN;
		if (tcp_flags & RTE_TCP_RST_FLAG)
			ipv6->ip_ext.flags |= NFP_FL_TCP_FLAG_RST;
		if (tcp_flags & RTE_TCP_PSH_FLAG)
			ipv6->ip_ext.flags |= NFP_FL_TCP_FLAG_PSH;
		if (tcp_flags & RTE_TCP_URG_FLAG)
			ipv6->ip_ext.flags |= NFP_FL_TCP_FLAG_URG;
	}

	return 0;
}

static int
nfp_flow_merge_udp(struct rte_flow *nfp_flow,
		char **mbuf_off,
		const struct rte_flow_item *item,
		const struct nfp_flow_item_proc *proc,
		bool is_mask)
{
	char *ports_off;
	struct nfp_flower_tp_ports *ports;
	const struct rte_flow_item_udp *spec;
	const struct rte_flow_item_udp *mask;
	struct nfp_flower_meta_tci *meta_tci;

	spec = item->spec;
	if (spec == NULL) {
		PMD_DRV_LOG(DEBUG, "nfp flow merge udp: no item->spec!");
		return 0;
	}

	meta_tci = (struct nfp_flower_meta_tci *)nfp_flow->payload.unmasked_data;
	if (meta_tci->nfp_flow_key_layer & NFP_FLOWER_LAYER_IPV4) {
		ports_off = *mbuf_off - sizeof(struct nfp_flower_ipv4) -
			sizeof(struct nfp_flower_tp_ports);
	} else {/* IPv6 */
		ports_off = *mbuf_off - sizeof(struct nfp_flower_ipv6) -
			sizeof(struct nfp_flower_tp_ports);
	}
	ports = (struct nfp_flower_tp_ports *)ports_off;

	mask = item->mask ? item->mask : proc->mask_default;
	if (is_mask) {
		ports->port_src = mask->hdr.src_port;
		ports->port_dst = mask->hdr.dst_port;
	} else {
		ports->port_src = spec->hdr.src_port;
		ports->port_dst = spec->hdr.dst_port;
	}

	return 0;
}

static int
nfp_flow_merge_sctp(struct rte_flow *nfp_flow,
		char **mbuf_off,
		const struct rte_flow_item *item,
		const struct nfp_flow_item_proc *proc,
		bool is_mask)
{
	char *ports_off;
	struct nfp_flower_tp_ports *ports;
	struct nfp_flower_meta_tci *meta_tci;
	const struct rte_flow_item_sctp *spec;
	const struct rte_flow_item_sctp *mask;

	spec = item->spec;
	if (spec == NULL) {
		PMD_DRV_LOG(DEBUG, "nfp flow merge sctp: no item->spec!");
		return 0;
	}

	meta_tci = (struct nfp_flower_meta_tci *)nfp_flow->payload.unmasked_data;
	if (meta_tci->nfp_flow_key_layer & NFP_FLOWER_LAYER_IPV4) {
		ports_off = *mbuf_off - sizeof(struct nfp_flower_ipv4) -
			sizeof(struct nfp_flower_tp_ports);
	} else { /* IPv6 */
		ports_off = *mbuf_off - sizeof(struct nfp_flower_ipv6) -
			sizeof(struct nfp_flower_tp_ports);
	}
	ports = (struct nfp_flower_tp_ports *)ports_off;

	mask = item->mask ? item->mask : proc->mask_default;
	if (is_mask) {
		ports->port_src = mask->hdr.src_port;
		ports->port_dst = mask->hdr.dst_port;
	} else {
		ports->port_src = spec->hdr.src_port;
		ports->port_dst = spec->hdr.dst_port;
	}

	return 0;
}

/* Graph of supported items and associated process function */
static const struct nfp_flow_item_proc nfp_flow_item_proc_list[] = {
	[RTE_FLOW_ITEM_TYPE_END] = {
		.next_item = NEXT_ITEM(RTE_FLOW_ITEM_TYPE_ETH),
	},
	[RTE_FLOW_ITEM_TYPE_ETH] = {
		.next_item = NEXT_ITEM(RTE_FLOW_ITEM_TYPE_VLAN,
			RTE_FLOW_ITEM_TYPE_IPV4,
			RTE_FLOW_ITEM_TYPE_IPV6),
		.mask_support = &(const struct rte_flow_item_eth){
			.hdr = {
				.dst_addr.addr_bytes = "\xff\xff\xff\xff\xff\xff",
				.src_addr.addr_bytes = "\xff\xff\xff\xff\xff\xff",
				.ether_type          = RTE_BE16(0xffff),
			},
			.has_vlan = 1,
		},
		.mask_default = &rte_flow_item_eth_mask,
		.mask_sz = sizeof(struct rte_flow_item_eth),
		.merge = nfp_flow_merge_eth,
	},
	[RTE_FLOW_ITEM_TYPE_VLAN] = {
		.next_item = NEXT_ITEM(RTE_FLOW_ITEM_TYPE_IPV4,
			RTE_FLOW_ITEM_TYPE_IPV6),
		.mask_support = &(const struct rte_flow_item_vlan){
			.hdr = {
				.vlan_tci  = RTE_BE16(0xefff),
				.eth_proto = RTE_BE16(0xffff),
			},
			.has_more_vlan = 1,
		},
		.mask_default = &rte_flow_item_vlan_mask,
		.mask_sz = sizeof(struct rte_flow_item_vlan),
		.merge = nfp_flow_merge_vlan,
	},
	[RTE_FLOW_ITEM_TYPE_IPV4] = {
		.next_item = NEXT_ITEM(RTE_FLOW_ITEM_TYPE_TCP,
			RTE_FLOW_ITEM_TYPE_UDP,
			RTE_FLOW_ITEM_TYPE_SCTP),
		.mask_support = &(const struct rte_flow_item_ipv4){
			.hdr = {
				.type_of_service = 0xff,
				.fragment_offset = RTE_BE16(0xffff),
				.time_to_live    = 0xff,
				.next_proto_id   = 0xff,
				.src_addr        = RTE_BE32(0xffffffff),
				.dst_addr        = RTE_BE32(0xffffffff),
			},
		},
		.mask_default = &rte_flow_item_ipv4_mask,
		.mask_sz = sizeof(struct rte_flow_item_ipv4),
		.merge = nfp_flow_merge_ipv4,
	},
	[RTE_FLOW_ITEM_TYPE_IPV6] = {
		.next_item = NEXT_ITEM(RTE_FLOW_ITEM_TYPE_TCP,
			RTE_FLOW_ITEM_TYPE_UDP,
			RTE_FLOW_ITEM_TYPE_SCTP),
		.mask_support = &(const struct rte_flow_item_ipv6){
			.hdr = {
				.vtc_flow   = RTE_BE32(0x0ff00000),
				.proto      = 0xff,
				.hop_limits = 0xff,
				.src_addr   = "\xff\xff\xff\xff\xff\xff\xff\xff"
					"\xff\xff\xff\xff\xff\xff\xff\xff",
				.dst_addr   = "\xff\xff\xff\xff\xff\xff\xff\xff"
					"\xff\xff\xff\xff\xff\xff\xff\xff",
			},
			.has_frag_ext = 1,
		},
		.mask_default = &rte_flow_item_ipv6_mask,
		.mask_sz = sizeof(struct rte_flow_item_ipv6),
		.merge = nfp_flow_merge_ipv6,
	},
	[RTE_FLOW_ITEM_TYPE_TCP] = {
		.mask_support = &(const struct rte_flow_item_tcp){
			.hdr = {
				.tcp_flags = 0xff,
				.src_port  = RTE_BE16(0xffff),
				.dst_port  = RTE_BE16(0xffff),
			},
		},
		.mask_default = &rte_flow_item_tcp_mask,
		.mask_sz = sizeof(struct rte_flow_item_tcp),
		.merge = nfp_flow_merge_tcp,
	},
	[RTE_FLOW_ITEM_TYPE_UDP] = {
		.mask_support = &(const struct rte_flow_item_udp){
			.hdr = {
				.src_port = RTE_BE16(0xffff),
				.dst_port = RTE_BE16(0xffff),
			},
		},
		.mask_default = &rte_flow_item_udp_mask,
		.mask_sz = sizeof(struct rte_flow_item_udp),
		.merge = nfp_flow_merge_udp,
	},
	[RTE_FLOW_ITEM_TYPE_SCTP] = {
		.mask_support = &(const struct rte_flow_item_sctp){
			.hdr = {
				.src_port  = RTE_BE16(0xffff),
				.dst_port  = RTE_BE16(0xffff),
			},
		},
		.mask_default = &rte_flow_item_sctp_mask,
		.mask_sz = sizeof(struct rte_flow_item_sctp),
		.merge = nfp_flow_merge_sctp,
	},
};

static int
nfp_flow_item_check(const struct rte_flow_item *item,
		const struct nfp_flow_item_proc *proc)
{
	int ret = 0;
	unsigned int i;
	const uint8_t *mask;

	/* item->last and item->mask cannot exist without item->spec. */
	if (item->spec == NULL) {
		if (item->mask || item->last) {
			PMD_DRV_LOG(ERR, "'mask' or 'last' field provided"
					" without a corresponding 'spec'.");
			return -EINVAL;
		}
		/* No spec, no mask, no problem. */
		return 0;
	}

	mask = item->mask ?
		(const uint8_t *)item->mask :
		(const uint8_t *)proc->mask_default;

	/*
	 * Single-pass check to make sure that:
	 * - Mask is supported, no bits are set outside proc->mask_support.
	 * - Both item->spec and item->last are included in mask.
	 */
	for (i = 0; i != proc->mask_sz; ++i) {
		if (mask[i] == 0)
			continue;

		if ((mask[i] | ((const uint8_t *)proc->mask_support)[i]) !=
				((const uint8_t *)proc->mask_support)[i]) {
			PMD_DRV_LOG(ERR, "Unsupported field found in 'mask'.");
			ret = -EINVAL;
			break;
		}

		if (item->last && (((const uint8_t *)item->spec)[i] & mask[i]) !=
				(((const uint8_t *)item->last)[i] & mask[i])) {
			PMD_DRV_LOG(ERR, "Range between 'spec' and 'last'"
					" is larger than 'mask'.");
			ret = -ERANGE;
			break;
		}
	}

	return ret;
}

static int
nfp_flow_compile_item_proc(const struct rte_flow_item items[],
		struct rte_flow *nfp_flow,
		char **mbuf_off_exact,
		char **mbuf_off_mask)
{
	int i;
	int ret = 0;
	const struct rte_flow_item *item;
	const struct nfp_flow_item_proc *proc_list;

	proc_list = nfp_flow_item_proc_list;
	for (item = items; item->type != RTE_FLOW_ITEM_TYPE_END; ++item) {
		const struct nfp_flow_item_proc *proc = NULL;

		for (i = 0; proc_list->next_item && proc_list->next_item[i]; ++i) {
			if (proc_list->next_item[i] == item->type) {
				proc = &nfp_flow_item_proc_list[item->type];
				break;
			}
		}

		if (proc == NULL) {
			PMD_DRV_LOG(ERR, "No next item provided for %d", item->type);
			ret = -ENOTSUP;
			break;
		}

		/* Perform basic sanity checks */
		ret = nfp_flow_item_check(item, proc);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "nfp flow item %d check failed", item->type);
			ret = -EINVAL;
			break;
		}

		if (proc->merge == NULL) {
			PMD_DRV_LOG(ERR, "nfp flow item %d no proc function", item->type);
			ret = -ENOTSUP;
			break;
		}

		ret = proc->merge(nfp_flow, mbuf_off_exact, item,
				proc, false);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "nfp flow item %d exact merge failed", item->type);
			break;
		}

		ret = proc->merge(nfp_flow, mbuf_off_mask, item,
				proc, true);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "nfp flow item %d mask merge failed", item->type);
			break;
		}

		proc_list = proc;
	}

	return ret;
}

static int
nfp_flow_compile_items(__rte_unused struct nfp_flower_representor *representor,
		const struct rte_flow_item items[],
		struct rte_flow *nfp_flow)
{
	int ret;
	char *mbuf_off_mask;
	char *mbuf_off_exact;

	mbuf_off_exact = nfp_flow->payload.unmasked_data +
			sizeof(struct nfp_flower_meta_tci) +
			sizeof(struct nfp_flower_in_port);
	mbuf_off_mask  = nfp_flow->payload.mask_data +
			sizeof(struct nfp_flower_meta_tci) +
			sizeof(struct nfp_flower_in_port);

	/* Go over items */
	ret = nfp_flow_compile_item_proc(items, nfp_flow,
			&mbuf_off_exact, &mbuf_off_mask);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "nfp flow item compile failed.");
		return -EINVAL;
	}

	return 0;
}

static int
nfp_flow_action_output(char *act_data,
		const struct rte_flow_action *action,
		struct nfp_fl_rule_metadata *nfp_flow_meta)
{
	size_t act_size;
	struct rte_eth_dev *ethdev;
	struct nfp_fl_act_output *output;
	struct nfp_flower_representor *representor;
	const struct rte_flow_action_port_id *port_id;

	port_id = action->conf;
	if (port_id == NULL || port_id->id >= RTE_MAX_ETHPORTS)
		return -ERANGE;

	ethdev = &rte_eth_devices[port_id->id];
	representor = (struct nfp_flower_representor *)ethdev->data->dev_private;
	act_size = sizeof(struct nfp_fl_act_output);

	output = (struct nfp_fl_act_output *)act_data;
	output->head.jump_id = NFP_FL_ACTION_OPCODE_OUTPUT;
	output->head.len_lw  = act_size >> NFP_FL_LW_SIZ;
	output->flags        = rte_cpu_to_be_16(NFP_FL_OUT_FLAGS_LAST);
	output->port         = rte_cpu_to_be_32(representor->port_id);

	nfp_flow_meta->shortcut = rte_cpu_to_be_32(representor->port_id);

	return 0;
}

static void
nfp_flow_action_set_mac(char *act_data,
		const struct rte_flow_action *action,
		bool mac_src_flag,
		bool mac_set_flag)
{
	size_t act_size;
	struct nfp_fl_act_set_eth *set_eth;
	const struct rte_flow_action_set_mac *set_mac;

	if (mac_set_flag)
		set_eth = (struct nfp_fl_act_set_eth *)act_data - 1;
	else
		set_eth = (struct nfp_fl_act_set_eth *)act_data;

	act_size = sizeof(struct nfp_fl_act_set_eth);
	set_eth->head.jump_id = NFP_FL_ACTION_OPCODE_SET_ETHERNET;
	set_eth->head.len_lw  = act_size >> NFP_FL_LW_SIZ;
	set_eth->reserved     = 0;

	set_mac = (const struct rte_flow_action_set_mac *)action->conf;
	if (mac_src_flag) {
		rte_memcpy(&set_eth->eth_addr[RTE_ETHER_ADDR_LEN],
				set_mac->mac_addr, RTE_ETHER_ADDR_LEN);
	} else {
		rte_memcpy(&set_eth->eth_addr[0],
				set_mac->mac_addr, RTE_ETHER_ADDR_LEN);
	}
}

static int
nfp_flow_compile_action(__rte_unused struct nfp_flower_representor *representor,
		const struct rte_flow_action actions[],
		struct rte_flow *nfp_flow)
{
	int ret = 0;
	char *position;
	char *action_data;
	bool drop_flag = false;
	bool mac_set_flag = false;
	uint32_t total_actions = 0;
	const struct rte_flow_action *action;
	struct nfp_fl_rule_metadata *nfp_flow_meta;

	nfp_flow_meta = nfp_flow->payload.meta;
	action_data   = nfp_flow->payload.action_data;
	position      = action_data;

	for (action = actions; action->type != RTE_FLOW_ACTION_TYPE_END; ++action) {
		switch (action->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			PMD_DRV_LOG(DEBUG, "Process RTE_FLOW_ACTION_TYPE_DROP");
			drop_flag = true;
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			PMD_DRV_LOG(DEBUG, "Process RTE_FLOW_ACTION_TYPE_COUNT");
			break;
		case RTE_FLOW_ACTION_TYPE_PORT_ID:
			PMD_DRV_LOG(DEBUG, "Process RTE_FLOW_ACTION_TYPE_PORT_ID");
			ret = nfp_flow_action_output(position, action, nfp_flow_meta);
			if (ret != 0) {
				PMD_DRV_LOG(ERR, "Failed when process"
						" RTE_FLOW_ACTION_TYPE_PORT_ID");
				return ret;
			}

			position += sizeof(struct nfp_fl_act_output);
			break;
		case RTE_FLOW_ACTION_TYPE_SET_MAC_SRC:
			PMD_DRV_LOG(DEBUG, "Process RTE_FLOW_ACTION_TYPE_SET_MAC_SRC");
			nfp_flow_action_set_mac(position, action, true, mac_set_flag);
			if (!mac_set_flag) {
				position += sizeof(struct nfp_fl_act_set_eth);
				mac_set_flag = true;
			}
			break;
		default:
			PMD_DRV_LOG(ERR, "Unsupported action type: %d", action->type);
			return -ENOTSUP;
		}
		total_actions++;
	}

	if (drop_flag)
		nfp_flow_meta->shortcut = rte_cpu_to_be_32(NFP_FL_SC_ACT_DROP);
	else if (total_actions > 1)
		nfp_flow_meta->shortcut = rte_cpu_to_be_32(NFP_FL_SC_ACT_NULL);

	return 0;
}

static struct rte_flow *
nfp_flow_process(struct nfp_flower_representor *representor,
		const struct rte_flow_item items[],
		const struct rte_flow_action actions[],
		bool validate_flag)
{
	int ret;
	char *hash_data;
	char *mask_data;
	uint32_t mask_len;
	uint32_t stats_ctx = 0;
	uint8_t new_mask_id = 0;
	struct rte_flow *nfp_flow;
	struct rte_flow *flow_find;
	struct nfp_flow_priv *priv;
	struct nfp_fl_key_ls key_layer;
	struct nfp_fl_rule_metadata *nfp_flow_meta;

	ret = nfp_flow_key_layers_calculate(items, actions, &key_layer);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Key layers calculate failed.");
		return NULL;
	}

	if (key_layer.port == (uint32_t)~0)
		key_layer.port = representor->port_id;

	priv = representor->app_fw_flower->flow_priv;
	ret = nfp_stats_id_alloc(priv, &stats_ctx);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "nfp stats id alloc failed.");
		return NULL;
	}

	nfp_flow = nfp_flow_alloc(&key_layer);
	if (nfp_flow == NULL) {
		PMD_DRV_LOG(ERR, "Alloc nfp flow failed.");
		goto free_stats;
	}

	nfp_flow->install_flag = true;

	nfp_flow_compile_metadata(priv, nfp_flow, &key_layer, stats_ctx);

	ret = nfp_flow_compile_items(representor, items, nfp_flow);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "nfp flow item process failed.");
		goto free_flow;
	}

	ret = nfp_flow_compile_action(representor, actions, nfp_flow);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "nfp flow action process failed.");
		goto free_flow;
	}

	nfp_flow_meta = nfp_flow->payload.meta;
	mask_data = nfp_flow->payload.mask_data;
	mask_len = key_layer.key_size;
	if (!nfp_check_mask_add(priv, mask_data, mask_len,
			&nfp_flow_meta->flags, &new_mask_id)) {
		PMD_DRV_LOG(ERR, "nfp mask add check failed.");
		goto free_flow;
	}

	/* Once we have a mask_id, update the meta tci */
	nfp_flower_update_meta_tci(nfp_flow->payload.unmasked_data, new_mask_id);

	/* Calculate and store the hash_key for later use */
	hash_data = (char *)(nfp_flow->payload.unmasked_data);
	nfp_flow->hash_key = rte_jhash(hash_data, nfp_flow->length, priv->hash_seed);

	/* Find the flow in hash table */
	flow_find = nfp_flow_table_search(priv, nfp_flow);
	if (flow_find != NULL) {
		PMD_DRV_LOG(ERR, "This flow is already exist.");
		if (!nfp_check_mask_remove(priv, mask_data, mask_len,
				&nfp_flow_meta->flags)) {
			PMD_DRV_LOG(ERR, "nfp mask del check failed.");
		}
		goto free_flow;
	}

	/* Flow validate should not update the flower version */
	if (!validate_flag)
		priv->flower_version++;

	return nfp_flow;

free_flow:
	nfp_flow_free(nfp_flow);
free_stats:
	nfp_stats_id_free(priv, stats_ctx);

	return NULL;
}

static struct rte_flow *
nfp_flow_setup(struct nfp_flower_representor *representor,
		const struct rte_flow_attr *attr,
		const struct rte_flow_item items[],
		const struct rte_flow_action actions[],
		struct rte_flow_error *error,
		bool validate_flag)
{
	if (attr->group != 0)
		PMD_DRV_LOG(INFO, "Pretend we support group attribute.");

	if (attr->priority != 0)
		PMD_DRV_LOG(INFO, "Pretend we support priority attribute.");

	if (attr->transfer != 0)
		PMD_DRV_LOG(INFO, "Pretend we support transfer attribute.");

	if (attr->egress != 0) {
		rte_flow_error_set(error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ATTR_EGRESS,
				NULL, "Egress is not supported.");
		return NULL;
	}

	if (attr->ingress == 0) {
		rte_flow_error_set(error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ATTR_INGRESS,
				NULL, "Only ingress is supported.");
		return NULL;
	}

	return nfp_flow_process(representor, items, actions, validate_flag);
}

static int
nfp_flow_teardown(struct nfp_flow_priv *priv,
		struct rte_flow *nfp_flow,
		bool validate_flag)
{
	char *mask_data;
	uint32_t mask_len;
	uint32_t stats_ctx;
	struct nfp_fl_rule_metadata *nfp_flow_meta;

	nfp_flow_meta = nfp_flow->payload.meta;
	mask_data = nfp_flow->payload.mask_data;
	mask_len = nfp_flow_meta->mask_len << NFP_FL_LW_SIZ;
	if (!nfp_check_mask_remove(priv, mask_data, mask_len,
			&nfp_flow_meta->flags)) {
		PMD_DRV_LOG(ERR, "nfp mask del check failed.");
		return -EINVAL;
	}

	nfp_flow_meta->flow_version = rte_cpu_to_be_64(priv->flower_version);

	/* Flow validate should not update the flower version */
	if (!validate_flag)
		priv->flower_version++;

	stats_ctx = rte_be_to_cpu_32(nfp_flow_meta->host_ctx_id);
	return nfp_stats_id_free(priv, stats_ctx);
}

static int
nfp_flow_validate(struct rte_eth_dev *dev,
		const struct rte_flow_attr *attr,
		const struct rte_flow_item items[],
		const struct rte_flow_action actions[],
		struct rte_flow_error *error)
{
	int ret;
	struct rte_flow *nfp_flow;
	struct nfp_flow_priv *priv;
	struct nfp_flower_representor *representor;

	representor = (struct nfp_flower_representor *)dev->data->dev_private;
	priv = representor->app_fw_flower->flow_priv;

	nfp_flow = nfp_flow_setup(representor, attr, items, actions, error, true);
	if (nfp_flow == NULL) {
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				NULL, "This flow can not be offloaded.");
	}

	ret = nfp_flow_teardown(priv, nfp_flow, true);
	if (ret != 0) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				NULL, "Flow resource free failed.");
	}

	nfp_flow_free(nfp_flow);

	return 0;
}

static struct rte_flow *
nfp_flow_create(struct rte_eth_dev *dev,
		const struct rte_flow_attr *attr,
		const struct rte_flow_item items[],
		const struct rte_flow_action actions[],
		struct rte_flow_error *error)
{
	int ret;
	struct rte_flow *nfp_flow;
	struct nfp_flow_priv *priv;
	struct nfp_app_fw_flower *app_fw_flower;
	struct nfp_flower_representor *representor;

	representor = (struct nfp_flower_representor *)dev->data->dev_private;
	app_fw_flower = representor->app_fw_flower;
	priv = app_fw_flower->flow_priv;

	nfp_flow = nfp_flow_setup(representor, attr, items, actions, error, false);
	if (nfp_flow == NULL) {
		rte_flow_error_set(error, ENOTSUP, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				NULL, "This flow can not be offloaded.");
		return NULL;
	}

	/* Add the flow to hardware */
	if (nfp_flow->install_flag) {
		ret = nfp_flower_cmsg_flow_add(app_fw_flower, nfp_flow);
		if (ret != 0) {
			rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					NULL, "Add flow to firmware failed.");
			goto flow_teardown;
		}
	}

	/* Add the flow to flow hash table */
	ret = nfp_flow_table_add(priv, nfp_flow);
	if (ret != 0) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				NULL, "Add flow to the flow table failed.");
		goto flow_teardown;
	}

	return nfp_flow;

flow_teardown:
	nfp_flow_teardown(priv, nfp_flow, false);
	nfp_flow_free(nfp_flow);

	return NULL;
}

static int
nfp_flow_destroy(struct rte_eth_dev *dev,
		struct rte_flow *nfp_flow,
		struct rte_flow_error *error)
{
	int ret;
	struct rte_flow *flow_find;
	struct nfp_flow_priv *priv;
	struct nfp_app_fw_flower *app_fw_flower;
	struct nfp_flower_representor *representor;

	representor = (struct nfp_flower_representor *)dev->data->dev_private;
	app_fw_flower = representor->app_fw_flower;
	priv = app_fw_flower->flow_priv;

	/* Find the flow in flow hash table */
	flow_find = nfp_flow_table_search(priv, nfp_flow);
	if (flow_find == NULL) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				NULL, "Flow does not exist.");
		ret = -EINVAL;
		goto exit;
	}

	/* Update flow */
	ret = nfp_flow_teardown(priv, nfp_flow, false);
	if (ret != 0) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				NULL, "Flow teardown failed.");
		ret = -EINVAL;
		goto exit;
	}

	/* Delete the flow from hardware */
	if (nfp_flow->install_flag) {
		ret = nfp_flower_cmsg_flow_delete(app_fw_flower, nfp_flow);
		if (ret != 0) {
			rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					NULL, "Delete flow from firmware failed.");
			ret = -EINVAL;
			goto exit;
		}
	}

	/* Delete the flow from flow hash table */
	ret = nfp_flow_table_delete(priv, nfp_flow);
	if (ret != 0) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				NULL, "Delete flow from the flow table failed.");
		ret = -EINVAL;
		goto exit;
	}

exit:
	nfp_flow_free(nfp_flow);

	return ret;
}

static int
nfp_flow_flush(struct rte_eth_dev *dev,
		struct rte_flow_error *error)
{
	int ret = 0;
	void *next_data;
	uint32_t iter = 0;
	const void *next_key;
	struct nfp_flow_priv *priv;

	priv = nfp_flow_dev_to_priv(dev);

	while (rte_hash_iterate(priv->flow_table, &next_key, &next_data, &iter) >= 0) {
		ret = nfp_flow_destroy(dev, (struct rte_flow *)next_data, error);
		if (ret != 0)
			break;
	}

	return ret;
}

static void
nfp_flow_stats_get(struct rte_eth_dev *dev,
		struct rte_flow *nfp_flow,
		void *data)
{
	uint32_t ctx_id;
	struct rte_flow *flow;
	struct nfp_flow_priv *priv;
	struct nfp_fl_stats *stats;
	struct rte_flow_query_count *query;

	priv = nfp_flow_dev_to_priv(dev);
	flow = nfp_flow_table_search(priv, nfp_flow);
	if (flow == NULL) {
		PMD_DRV_LOG(ERR, "Can not find statistics for this flow.");
		return;
	}

	query = (struct rte_flow_query_count *)data;
	memset(query, 0, sizeof(*query));

	ctx_id = rte_be_to_cpu_32(nfp_flow->payload.meta->host_ctx_id);
	stats = &priv->stats[ctx_id];

	rte_spinlock_lock(&priv->stats_lock);
	if (stats->pkts != 0 && stats->bytes != 0) {
		query->hits = stats->pkts;
		query->bytes = stats->bytes;
		query->hits_set = 1;
		query->bytes_set = 1;
		if (query->reset != 0) {
			stats->pkts = 0;
			stats->bytes = 0;
		}
	}
	rte_spinlock_unlock(&priv->stats_lock);
}

static int
nfp_flow_query(struct rte_eth_dev *dev,
		struct rte_flow *nfp_flow,
		const struct rte_flow_action *actions,
		void *data,
		struct rte_flow_error *error)
{
	const struct rte_flow_action *action;

	for (action = actions; action->type != RTE_FLOW_ACTION_TYPE_END; ++action) {
		switch (action->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_COUNT:
			nfp_flow_stats_get(dev, nfp_flow, data);
			break;
		default:
			rte_flow_error_set(error, ENOTSUP, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					NULL, "Unsupported action type for flow query.");
			return -ENOTSUP;
		}
	}

	return 0;
}

static const struct rte_flow_ops nfp_flow_ops = {
	.validate                    = nfp_flow_validate,
	.create                      = nfp_flow_create,
	.destroy                     = nfp_flow_destroy,
	.flush                       = nfp_flow_flush,
	.query                       = nfp_flow_query,
};

int
nfp_net_flow_ops_get(struct rte_eth_dev *dev,
		const struct rte_flow_ops **ops)
{
	if ((dev->data->dev_flags & RTE_ETH_DEV_REPRESENTOR) == 0) {
		*ops = NULL;
		PMD_DRV_LOG(ERR, "Port is not a representor.");
		return -EINVAL;
	}

	*ops = &nfp_flow_ops;

	return 0;
}

int
nfp_flow_priv_init(struct nfp_pf_dev *pf_dev)
{
	int ret = 0;
	size_t stats_size;
	uint64_t ctx_count;
	uint64_t ctx_split;
	struct nfp_flow_priv *priv;
	struct nfp_app_fw_flower *app_fw_flower;

	struct rte_hash_parameters mask_hash_params = {
		.name       = "mask_hash_table",
		.entries    = NFP_MASK_TABLE_ENTRIES,
		.hash_func  = rte_jhash,
		.socket_id  = rte_socket_id(),
		.key_len    = sizeof(uint32_t),
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
	};

	struct rte_hash_parameters flow_hash_params = {
		.name       = "flow_hash_table",
		.hash_func  = rte_jhash,
		.socket_id  = rte_socket_id(),
		.key_len    = sizeof(uint32_t),
		.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
	};

	ctx_count = nfp_rtsym_read_le(pf_dev->sym_tbl,
			"CONFIG_FC_HOST_CTX_COUNT", &ret);
	if (ret < 0) {
		PMD_INIT_LOG(ERR, "Read CTX_COUNT from symbol table failed");
		goto exit;
	}

	ctx_split = nfp_rtsym_read_le(pf_dev->sym_tbl,
			"CONFIG_FC_HOST_CTX_SPLIT", &ret);
	if (ret < 0) {
		PMD_INIT_LOG(ERR, "Read CTX_SPLIT from symbol table failed");
		goto exit;
	}

	priv = rte_zmalloc("nfp_app_flow_priv", sizeof(struct nfp_flow_priv), 0);
	if (priv == NULL) {
		PMD_INIT_LOG(ERR, "nfp app flow priv creation failed");
		ret = -ENOMEM;
		goto exit;
	}

	app_fw_flower = NFP_PRIV_TO_APP_FW_FLOWER(pf_dev->app_fw_priv);
	app_fw_flower->flow_priv = priv;
	priv->hash_seed = (uint32_t)rte_rand();
	priv->stats_ring_size = ctx_count;
	priv->total_mem_units = ctx_split;

	/* Init ring buffer and unallocated mask_ids. */
	priv->mask_ids.init_unallocated = NFP_FLOWER_MASK_ENTRY_RS - 1;
	priv->mask_ids.free_list.buf = rte_zmalloc("nfp_app_mask_ids",
			NFP_FLOWER_MASK_ENTRY_RS * NFP_FLOWER_MASK_ELEMENT_RS, 0);
	if (priv->mask_ids.free_list.buf == NULL) {
		PMD_INIT_LOG(ERR, "mask id free list creation failed");
		ret = -ENOMEM;
		goto free_priv;
	}

	/* Init ring buffer and unallocated stats_ids. */
	priv->stats_ids.init_unallocated = ctx_count / ctx_split;
	priv->stats_ids.free_list.buf = rte_zmalloc("nfp_app_stats_ids",
			priv->stats_ring_size * NFP_FL_STATS_ELEM_RS, 0);
	if (priv->stats_ids.free_list.buf == NULL) {
		PMD_INIT_LOG(ERR, "stats id free list creation failed");
		ret = -ENOMEM;
		goto free_mask_id;
	}

	/* flow stats */
	rte_spinlock_init(&priv->stats_lock);
	stats_size = (ctx_count & NFP_FL_STAT_ID_STAT) |
			((ctx_split - 1) & NFP_FL_STAT_ID_MU_NUM);
	PMD_INIT_LOG(INFO, "ctx_count:%0lx, ctx_split:%0lx, stats_size:%0lx ",
			ctx_count, ctx_split, stats_size);
	priv->stats = rte_zmalloc("nfp_flow_stats",
			stats_size * sizeof(struct nfp_fl_stats), 0);
	if (priv->stats == NULL) {
		PMD_INIT_LOG(ERR, "flow stats creation failed");
		ret = -ENOMEM;
		goto free_stats_id;
	}

	/* mask table */
	mask_hash_params.hash_func_init_val = priv->hash_seed;
	priv->mask_table = rte_hash_create(&mask_hash_params);
	if (priv->mask_table == NULL) {
		PMD_INIT_LOG(ERR, "mask hash table creation failed");
		ret = -ENOMEM;
		goto free_stats;
	}

	/* flow table */
	flow_hash_params.hash_func_init_val = priv->hash_seed;
	flow_hash_params.entries = ctx_count;
	priv->flow_table = rte_hash_create(&flow_hash_params);
	if (priv->flow_table == NULL) {
		PMD_INIT_LOG(ERR, "flow hash table creation failed");
		ret = -ENOMEM;
		goto free_mask_table;
	}

	return 0;

free_mask_table:
	rte_free(priv->mask_table);
free_stats:
	rte_free(priv->stats);
free_stats_id:
	rte_free(priv->stats_ids.free_list.buf);
free_mask_id:
	rte_free(priv->mask_ids.free_list.buf);
free_priv:
	rte_free(priv);
exit:
	return ret;
}

void
nfp_flow_priv_uninit(struct nfp_pf_dev *pf_dev)
{
	struct nfp_flow_priv *priv;
	struct nfp_app_fw_flower *app_fw_flower;

	app_fw_flower = NFP_PRIV_TO_APP_FW_FLOWER(pf_dev->app_fw_priv);
	priv = app_fw_flower->flow_priv;

	rte_hash_free(priv->flow_table);
	rte_hash_free(priv->mask_table);
	rte_free(priv->stats);
	rte_free(priv->stats_ids.free_list.buf);
	rte_free(priv->mask_ids.free_list.buf);
	rte_free(priv);
}