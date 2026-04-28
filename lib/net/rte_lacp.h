/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Robin Jarry
 * All rights reserved.
 */

#ifndef _RTE_LACP_H_
#define _RTE_LACP_H_

/**
 * @file
 *
 * LACP protocol definitions (IEEE 802.1AX / 802.3ad).
 *
 * LACP runs over the Slow Protocols ethertype. Each LACPDU starts with
 * a subtype and version byte, followed by three tagged sections (actor,
 * partner, collector) and a terminator. Each section is a TLV with a
 * fixed type and length.
 *
 * The actor and partner sections share the same layout described by
 * struct rte_lacp_participant. The complete frame is struct rte_lacp_pdu.
 */

#include <stdint.h>

#include <errno.h>

#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

/** @{@name Slow Protocol subtypes */
#define RTE_SLOW_SUBTYPE_LACP 1 /**< LACP */
/**@}*/

/** @{@name LACP versions */
#define RTE_LACP_VERSION_1 1
/**@}*/

/** @{@name LACP TLV types */
#define RTE_LACP_TYPE_TERMINATOR 0 /**< Terminator */
#define RTE_LACP_TYPE_ACTOR 1 /**< Actor Information */
#define RTE_LACP_TYPE_PARTNER 2 /**< Partner Information */
#define RTE_LACP_TYPE_COLLECTOR 3 /**< Collector Information */
/**@}*/

/** @{@name LACP TLV lengths */
#define RTE_LACP_LEN_ACTOR 20
#define RTE_LACP_LEN_PARTNER 20
#define RTE_LACP_LEN_COLLECTOR 16
#define RTE_LACP_LEN_TERMINATOR 0
/**@}*/

/** @{@name LACP state flags */
#define RTE_LACP_STATE_ACTIVE (1 << 0) /**< Active LACP mode. */
#define RTE_LACP_STATE_FAST (1 << 1) /**< Short timeout. */
#define RTE_LACP_STATE_AGGREGATABLE (1 << 2) /**< Link is aggregatable. */
#define RTE_LACP_STATE_SYNCHRONIZED (1 << 3) /**< In sync with partner. */
#define RTE_LACP_STATE_COLLECTING (1 << 4) /**< Rx mux is on. */
#define RTE_LACP_STATE_DISTRIBUTING (1 << 5) /**< Tx mux is on. */
#define RTE_LACP_STATE_DEFAULTED (1 << 6) /**< Using default partner. */
#define RTE_LACP_STATE_EXPIRED (1 << 7) /**< State has expired. */
/**@}*/

/** @{@name LACP timeouts (seconds) */
#define RTE_LACP_FAST_PERIOD 1
#define RTE_LACP_SLOW_PERIOD 30
#define RTE_LACP_SHORT_TIMEOUT 3
#define RTE_LACP_LONG_TIMEOUT 90
/**@}*/

/** LACP actor or partner information. */
struct __rte_packed_begin rte_lacp_participant {
	rte_be16_t system_priority; /**< System priority. */
	struct rte_ether_addr system_mac; /**< System MAC address. */
	rte_be16_t key; /**< Operational key. */
	rte_be16_t port_priority; /**< Port priority. */
	rte_be16_t port_number; /**< Port number. */
	uint8_t state; /**< RTE_LACP_STATE_* */
	uint8_t __padding[3];
} __rte_packed_end __rte_aligned(2);

/** LACP Protocol Data Unit. */
struct __rte_packed_begin rte_lacp_pdu {
	uint8_t subtype; /**< ::RTE_SLOW_SUBTYPE_LACP */
	uint8_t version; /**< ::RTE_LACP_VERSION_1 */

	/* Actor Information */
	uint8_t actor_type; /**< ::RTE_LACP_TYPE_ACTOR */
	uint8_t actor_len; /**< ::RTE_LACP_LEN_ACTOR */
	struct rte_lacp_participant actor;

	/* Partner Information */
	uint8_t partner_type; /**< ::RTE_LACP_TYPE_PARTNER */
	uint8_t partner_len; /**< ::RTE_LACP_LEN_PARTNER */
	struct rte_lacp_participant partner;

	/* Collector Information */
	uint8_t collector_type; /**< ::RTE_LACP_TYPE_COLLECTOR */
	uint8_t collector_len; /**< ::RTE_LACP_LEN_COLLECTOR */
	rte_be16_t collector_max_delay; /**< Max collector delay. */
	uint8_t __reserved[12];

	/* Terminator */
	uint8_t terminator_type; /**< ::RTE_LACP_TYPE_TERMINATOR */
	uint8_t terminator_len; /**< ::RTE_LACP_LEN_TERMINATOR */
	uint8_t __padding[50];
} __rte_packed_end __rte_aligned(2);

/** Standard LACP destination multicast address. */
#define RTE_LACP_DST_MAC ((struct rte_ether_addr) {{0x01, 0x80, 0xc2, 0x00, 0x00, 0x02}})

/**
 * Validate a received LACPDU.
 *
 * Read the PDU from @p m at @p offset and check that all TLV type and
 * length fields have the expected values.
 *
 * @param m
 *   The packet buffer.
 * @param offset
 *   Byte offset of the LACPDU in @p m.
 * @return
 *   0 on success, -EMSGSIZE if the packet is too short, -EBADMSG if
 *   any TLV field has an unexpected value.
 */
static inline int rte_lacp_check_pdu(const struct rte_mbuf *m, uint16_t offset)
{
	const struct rte_lacp_pdu *lacp;
	struct rte_lacp_pdu buf;

	if (rte_pktmbuf_pkt_len(m) - offset < sizeof(*lacp))
		return -EMSGSIZE;

	lacp = rte_pktmbuf_read(m, offset, sizeof(*lacp), &buf);
	if (lacp == NULL)
		return -EMSGSIZE;

	if (lacp->subtype != RTE_SLOW_SUBTYPE_LACP)
		return -EBADMSG;
	if (lacp->version != RTE_LACP_VERSION_1)
		return -EBADMSG;
	if (lacp->actor_type != RTE_LACP_TYPE_ACTOR)
		return -EBADMSG;
	if (lacp->actor_len != RTE_LACP_LEN_ACTOR)
		return -EBADMSG;
	if (lacp->partner_type != RTE_LACP_TYPE_PARTNER)
		return -EBADMSG;
	if (lacp->partner_len != RTE_LACP_LEN_PARTNER)
		return -EBADMSG;
	if (lacp->collector_type != RTE_LACP_TYPE_COLLECTOR)
		return -EBADMSG;
	if (lacp->collector_len != RTE_LACP_LEN_COLLECTOR)
		return -EBADMSG;
	if (lacp->terminator_type != RTE_LACP_TYPE_TERMINATOR)
		return -EBADMSG;
	if (lacp->terminator_len != RTE_LACP_LEN_TERMINATOR)
		return -EBADMSG;

	return 0;
}

/** Per-port LACP state for applications. */
struct rte_lacp_member {
	bool active; /**< Link is operational. */
	uint64_t next_tx; /**< Next TX deadline (TSC). */
	uint64_t last_rx; /**< Last RX timestamp (TSC). */
	struct rte_lacp_participant local; /**< Local actor info. */
	struct rte_lacp_participant remote; /**< Received partner info. */
};

/**
 * Return the LACP timeout for a participant in TSC ticks.
 *
 * @param p
 *   Participant whose state flags determine the timeout.
 * @return
 *   Timeout value in TSC ticks.
 */
static inline uint64_t
rte_lacp_timeout_value(const struct rte_lacp_participant *p)
{
	uint64_t hz = rte_get_tsc_hz();

	if (p->state & RTE_LACP_STATE_FAST)
		return RTE_LACP_SHORT_TIMEOUT * hz;
	return RTE_LACP_LONG_TIMEOUT * hz;
}

/** Result flags from rte_lacp_member_check() and rte_lacp_pdu_process(). */
typedef enum {
	RTE_LACP_RES_TX_NOW = 1 << 0, /**< A LACPDU should be sent now. */
	RTE_LACP_RES_TIMEOUT = 1 << 1, /**< Partner has timed out. */
	RTE_LACP_RES_ACTIVE_CHANGE = 1 << 2, /**< Link active state changed. */
} rte_lacp_res_t;

/**
 * Initialize or reconfigure a LACP member port.
 *
 * Sets up the local participant fields. If no PDU has been received yet
 * (last_rx == 0), the state is reset to defaulted/expired.
 *
 * @param member
 *   Member state to initialize.
 * @param mac
 *   System MAC address.
 * @param id
 *   Zero-based port index (stored as 1-based port_number).
 * @param prio
 *   System and port priority.
 * @param speed
 *   Link speed in Mb/s, used as the aggregation key.
 * @param fast
 *   If true, use short timeout (LACP fast mode).
 */
static inline void
rte_lacp_member_init(struct rte_lacp_member *member, const struct rte_ether_addr *mac,
		     uint16_t id, uint16_t prio, uint16_t speed, bool fast)
{
	/* Port number must be non-zero; some switches reject it otherwise. */
	member->local.port_number = rte_cpu_to_be_16(id + 1);
	member->local.port_priority = rte_cpu_to_be_16(prio);
	member->local.system_priority = rte_cpu_to_be_16(prio);
	member->local.system_mac = *mac;
	/* Key is the link speed so ports with the same speed can aggregate. */
	member->local.key = rte_cpu_to_be_16(speed);
	if (member->last_rx == 0) {
		member->local.state = RTE_LACP_STATE_ACTIVE
			| RTE_LACP_STATE_AGGREGATABLE
			| RTE_LACP_STATE_DEFAULTED
			| RTE_LACP_STATE_EXPIRED;
		member->active = false;
		member->next_tx = 0;
	}
	if (fast)
		member->local.state |= RTE_LACP_STATE_FAST;
	else
		member->local.state &= ~RTE_LACP_STATE_FAST;
}

/**
 * Check a LACP member for timeouts and pending TX.
 *
 * Should be called periodically. Detects partner timeout and schedules
 * the next LACPDU transmission.
 *
 * @param member
 *   Member state to check.
 * @return
 *   Bitmask of rte_lacp_res_t flags.
 */
static inline rte_lacp_res_t rte_lacp_member_check(struct rte_lacp_member *member)
{
	uint64_t now = rte_rdtsc();
	rte_lacp_res_t res = 0;

	/* Check for timeout if we've received at least one PDU */
	if (member->last_rx != 0 && member->last_rx < now) {
		if (now - member->last_rx > rte_lacp_timeout_value(&member->local)) {
			/* Partner timed out, enter failed state. */
			member->active = false;
			member->local.state &= ~RTE_LACP_STATE_SYNCHRONIZED;
			member->local.state &= ~RTE_LACP_STATE_COLLECTING;
			member->local.state &= ~RTE_LACP_STATE_DISTRIBUTING;
			member->local.state |= RTE_LACP_STATE_EXPIRED;
			member->local.state |= RTE_LACP_STATE_DEFAULTED;
			res |= RTE_LACP_RES_TX_NOW;
			res |= RTE_LACP_RES_TIMEOUT;
			res |= RTE_LACP_RES_ACTIVE_CHANGE;
		}
	}

	if (member->next_tx <= now || member->last_rx == 0)
		res |= RTE_LACP_RES_TX_NOW;

	if (res & RTE_LACP_RES_TX_NOW)
		member->next_tx = now + rte_lacp_timeout_value(&member->remote);

	return res;
}

/**
 * Process a received LACPDU and update member state.
 *
 * @param member
 *   Member state to update.
 * @param pdu
 *   The received and validated LACPDU.
 * @return
 *   Bitmask of rte_lacp_res_t flags.
 */
static inline rte_lacp_res_t
rte_lacp_pdu_process(struct rte_lacp_member *member, const struct rte_lacp_pdu *pdu)
{
	rte_lacp_res_t res = RTE_LACP_RES_TX_NOW;
	bool old_active = member->active;
	bool remote_sync, remote_collect;

	member->remote = pdu->actor;
	member->last_rx = rte_rdtsc();
	remote_sync = member->remote.state & RTE_LACP_STATE_SYNCHRONIZED;
	remote_collect = member->remote.state & RTE_LACP_STATE_COLLECTING;

	member->local.state |= RTE_LACP_STATE_SYNCHRONIZED;
	member->local.state &= ~(RTE_LACP_STATE_EXPIRED | RTE_LACP_STATE_DEFAULTED);
	if (remote_sync) {
		member->local.state |= RTE_LACP_STATE_COLLECTING;
		if (remote_collect)
			member->local.state |= RTE_LACP_STATE_DISTRIBUTING;
	}

	member->active = remote_sync && remote_collect;

	if (old_active != member->active)
		res |= RTE_LACP_RES_ACTIVE_CHANGE;

	return res;
}

/**
 * Fill a LACPDU from member state.
 *
 * @param pdu
 *   PDU to fill.
 * @param member
 *   Member whose local/remote info is copied into the PDU.
 */
static inline void
rte_lacp_pdu_fill(struct rte_lacp_pdu *pdu, const struct rte_lacp_member *member)
{
	pdu->subtype = RTE_SLOW_SUBTYPE_LACP;
	pdu->version = RTE_LACP_VERSION_1;
	pdu->actor_type = RTE_LACP_TYPE_ACTOR;
	pdu->actor_len = RTE_LACP_LEN_ACTOR;
	pdu->actor = member->local;
	pdu->partner_type = RTE_LACP_TYPE_PARTNER;
	pdu->partner_len = RTE_LACP_LEN_PARTNER;
	pdu->partner = member->remote;
	pdu->collector_type = RTE_LACP_TYPE_COLLECTOR;
	pdu->collector_len = RTE_LACP_LEN_COLLECTOR;
	pdu->collector_max_delay = RTE_BE16(0);
	pdu->terminator_type = RTE_LACP_TYPE_TERMINATOR;
	pdu->terminator_len = RTE_LACP_LEN_TERMINATOR;
}

#endif /* _RTE_LACP_H_ */
