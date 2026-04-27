/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Robin Jarry
 * All rights reserved.
 */

#ifndef _RTE_ICMP6_H_
#define _RTE_ICMP6_H_

/**
 * @file
 *
 * ICMPv6 protocol definitions (RFC 4443, RFC 4861).
 *
 * All ICMPv6 messages start with a common 4-byte preamble (struct rte_icmp6)
 * containing the type, code and checksum fields. What follows depends on the
 * message type and is described by a type-specific structure:
 *
 * - Error messages (type 1-4): rte_icmp6_dest_unreach, rte_icmp6_pkt_too_big,
 *   rte_icmp6_ttl_exceeded, rte_icmp6_param_problem.
 * - Echo messages (type 128-129): rte_icmp6_echo_request, rte_icmp6_echo_reply.
 * - NDP messages (type 133-136): rte_icmp6_router_solicit,
 *   rte_icmp6_router_advert, rte_icmp6_neigh_solicit, rte_icmp6_neigh_advert.
 *
 * NDP messages may carry a chain of TLV options after the type-specific header.
 * Each option starts with a 2-byte descriptor (struct rte_icmp6_opt) followed
 * by option-specific data (e.g. rte_icmp6_opt_lladdr for link-layer addresses).
 * The helper rte_icmp6_get_opt() walks this option chain inside an mbuf.
 */

#include <errno.h>
#include <stdint.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip6.h>
#include <rte_mbuf.h>

/** @{@name ICMP6 packet types */
/* errors */
#define RTE_ICMP6_TYPE_DEST_UNREACH 1 /**< Destination Unreachable Error */
#define RTE_ICMP6_TYPE_PKT_TOO_BIG 2 /**< Packet Too Big Error */
#define RTE_ICMP6_TYPE_TTL_EXCEEDED 3 /**< TIme Exceeded Error */
#define RTE_ICMP6_TYPE_PARAM_PROBLEM 4 /**< Parameter Problem Error */
/* messages */
#define RTE_ICMP6_TYPE_ECHO_REQUEST 128 /**< Echo Request */
#define RTE_ICMP6_TYPE_ECHO_REPLY 129 /**< Echo Reply */
#define RTE_ICMP6_TYPE_ROUTER_SOLICIT 133 /**< Router Solicitation */
#define RTE_ICMP6_TYPE_ROUTER_ADVERT 134 /**< Router Advertisement */
#define RTE_ICMP6_TYPE_NEIGH_SOLICIT 135 /**< Neighbor Solicitation */
#define RTE_ICMP6_TYPE_NEIGH_ADVERT 136 /**< Neighbor Advertisement */
/**@}*/

/**@{@name ICMP6 error codes */
/* RTE_ICMP6_TYPE_DEST_UNREACH */
#define RTE_ICMP6_CODE_DEST_UNREACH_NO_ROUTE 0 /**< No route to the destination */
#define RTE_ICMP6_CODE_DEST_UNREACH_ADMIN 1 /**< Administratively prohibited */
#define RTE_ICMP6_CODE_DEST_UNREACH_SCOPE 2 /**< Beyond scope of source address */
#define RTE_ICMP6_CODE_DEST_UNREACH_ADDR 3 /**< Address unreachable */
#define RTE_ICMP6_CODE_DEST_UNREACH_PORT 4 /**< Port unreachable */
#define RTE_ICMP6_CODE_DEST_UNREACH_POLICY 5 /**< Failed ingress/egress policy */
#define RTE_ICMP6_CODE_DEST_UNREACH_REJECT 6 /**< Reject route to destination */
#define RTE_ICMP6_CODE_DEST_UNREACH_SRH 7 /**< Error in Source Routing Header */
/* RTE_ICMP6_TYPE_TTL_EXCEEDED */
#define RTE_ICMP6_CODE_TTL_EXCEEDED_TRANSIT 0 /**< Hop limit exceeded in transit */
#define RTE_ICMP6_CODE_TTL_EXCEEDED_FRAG 1 /**< Fragment reassembly time exceeded */
/* RTE_ICMP6_TYPE_PARAM_PROBLEM */
#define RTE_ICMP6_CODE_PARAM_PROBLEM_FIELD 0 /**< Bad header field */
#define RTE_ICMP6_CODE_PARAM_PROBLEM_NH 1 /**< Unknown Next Header */
#define RTE_ICMP6_CODE_PARAM_PROBLEM_OPT 2 /**< Unknown IPv6 option */
#define RTE_ICMP6_CODE_PARAM_PROBLEM_FRAG 3 /**< Incomplete header chain */
#define RTE_ICMP6_CODE_PARAM_PROBLEM_SRH 4 /**< SR upper-layer error */
#define RTE_ICMP6_CODE_PARAM_PROBLEM_NH_INTER 5 /**< Unknown intermediate NH */
#define RTE_ICMP6_CODE_PARAM_PROBLEM_EXT_SIZE 6 /**< Ext header too big */
#define RTE_ICMP6_CODE_PARAM_PROBLEM_EXT_CHAIN 7 /**< Ext header chain too long */
#define RTE_ICMP6_CODE_PARAM_PROBLEM_EXT_NUM 8 /**< Too many ext headers */
#define RTE_ICMP6_CODE_PARAM_PROBLEM_EXT_OPT 9 /**< Too many ext options */
#define RTE_ICMP6_CODE_PARAM_PROBLEM_OPT_SIZE 10 /**< Option too big */
/**@}*/

/** Minimum ICMPv6 header length: preamble + type-specific part. */
#define RTE_ICMP6_HDR_MIN_LEN 8

/** ICMP6 preamble. Followed by a payload. */
struct __rte_packed_begin rte_icmp6 {
	uint8_t type; /**< RTE_ICMP6_TYPE_* */
	uint8_t code; /**< RTE_ICMP6_CODE_* meaning depends on type */
	rte_be16_t cksum; /**< Checksum. */
} __rte_packed_end;

/** Destination Unreachable Error (::RTE_ICMP6_TYPE_DEST_UNREACH) */
struct __rte_packed_begin rte_icmp6_dest_unreach {
	uint32_t __unused;
} __rte_packed_end;

/** Packet Too Big Error (::RTE_ICMP6_TYPE_PKT_TOO_BIG) */
struct __rte_packed_begin rte_icmp6_pkt_too_big {
	rte_be32_t mtu; /**< Maximum Transmission Unit. */
} __rte_packed_end;

/** Time Exceeded Error (::RTE_ICMP6_TYPE_TTL_EXCEEDED) */
struct __rte_packed_begin rte_icmp6_ttl_exceeded {
	uint32_t __unused;
} __rte_packed_end;

/** Parameter Problem Error (::RTE_ICMP6_TYPE_PARAM_PROBLEM) */
struct __rte_packed_begin rte_icmp6_param_problem {
	rte_be32_t offset; /**< Byte offset in the original packet. */
} __rte_packed_end;

/** Echo Request (::RTE_ICMP6_TYPE_ECHO_REQUEST) */
struct __rte_packed_begin rte_icmp6_echo_request {
	rte_be16_t ident; /**< Identifier. */
	rte_be16_t seqnum; /**< Sequence number. */
} __rte_packed_end;

/** Echo Reply (::RTE_ICMP6_TYPE_ECHO_REPLY) */
struct __rte_packed_begin rte_icmp6_echo_reply {
	rte_be16_t ident; /**< Identifier. */
	rte_be16_t seqnum; /**< Sequence number. */
} __rte_packed_end;

/** Router Solicitation (::RTE_ICMP6_TYPE_ROUTER_SOLICIT) */
struct __rte_packed_begin rte_icmp6_router_solicit {
	uint32_t __reserved;
} __rte_packed_end;

/**@{@name ICMP6 Router Advertisement flags */
#define RTE_ICMP6_RA_F_MANAGED_ADDR (1 << 0) /**< Managed address config. */
#define RTE_ICMP6_RA_F_OTHER_CONFIG (1 << 1) /**< Other config via DHCPv6. */
/**@}*/

/** Router Advertisement (::RTE_ICMP6_TYPE_ROUTER_ADVERT) */
struct __rte_packed_begin rte_icmp6_router_advert {
	uint8_t cur_hoplim; /**< Default hop limit for outgoing packets. */
	uint8_t flags; /**< RTE_ICMP6_RA_F_* */
	rte_be16_t lifetime; /**< Router lifetime (seconds). */
	rte_be32_t reachable_time; /**< Reachable time (milliseconds). */
	rte_be32_t retrans_timer; /**< Retransmit timer (milliseconds). */
} __rte_packed_end;

/** Neighbor Solicitation (::RTE_ICMP6_TYPE_NEIGH_SOLICIT) */
struct __rte_packed_begin rte_icmp6_neigh_solicit {
	uint32_t __reserved;
	struct rte_ipv6_addr target; /**< Target IPv6 address. */
} __rte_packed_end;

/**@{@name ICMP6 Neighbor Advertisement flags */
#define RTE_ICMP6_NA_F_ROUTER (1 << 0) /**< Sender is a router. */
#define RTE_ICMP6_NA_F_SOLICITED (1 << 1) /**< Response to a solicitation. */
#define RTE_ICMP6_NA_F_OVERRIDE (1 << 2) /**< Override existing cache entry. */
/**@}*/

/** Neighbor Advertisement (::RTE_ICMP6_TYPE_NEIGH_ADVERT) */
struct __rte_packed_begin rte_icmp6_neigh_advert {
	uint8_t flags; /**< RTE_ICMP6_NA_F_* */
	uint8_t __reserved;
	uint16_t __reserved2;
	struct rte_ipv6_addr target; /**< Target IPv6 address. */
} __rte_packed_end;

/**@{@name ICMP6 NDP Option types */
#define RTE_ICMP6_OPT_SRC_LLADDR 1 /**< Source Link-Layer Address */
#define RTE_ICMP6_OPT_TARGET_LLADDR 2 /**< Target Link-Layer Address */
#define RTE_ICMP6_OPT_PREFIX 3 /**< Prefix Information */
#define RTE_ICMP6_OPT_REDIRECT 4 /**< Redirected Header */
#define RTE_ICMP6_OPT_MTU 5 /**< Preferred MTU */
/**@}*/

/** NDP option header (type + length), followed by option-specific data. */
struct __rte_packed_begin rte_icmp6_opt {
	uint8_t type; /**< RTE_ICMP6_OPT_* */
	uint8_t len; /**< Full option size in units of 8 bytes. */
} __rte_packed_end;

/**
 * Compute the NDP option length field for a given payload size.
 *
 * The option length field encodes the full option size (header + data) in
 * units of 8 bytes (RFC 4861). This function adds the 2-byte option header,
 * rounds up to the next multiple of 8 and divides by 8.
 *
 * @param payload_len
 *   Payload size in bytes (not counting the option header).
 * @return
 *   Value to store in rte_icmp6_opt::len.
 */
static inline uint8_t rte_icmp6_opt_len(unsigned payload_len)
{
	return ((sizeof(struct rte_icmp6_opt) + payload_len + 7) & 0xf8) / 8;
}

/**
 * Link-layer address option payload.
 *
 * ::RTE_ICMP6_OPT_SRC_LLADDR or ::RTE_ICMP6_OPT_TARGET_LLADDR
 */
struct __rte_packed_begin rte_icmp6_opt_lladdr {
	struct rte_ether_addr mac; /**< Link-layer address. */
} __rte_packed_end __rte_aligned(2);

/**@{@name ICMP6 Prefix Information option flags */
#define RTE_ICMP6_OPT_PREFIX_F_ON_LINK (1 << 0) /**< On-link prefix. */
#define RTE_ICMP6_OPT_PREFIX_F_AUTO (1 << 1) /**< Usable for SLAAC. */
/**@}*/

/** Prefix Information option payload (::RTE_ICMP6_OPT_PREFIX). */
struct __rte_packed_begin rte_icmp6_opt_prefix {
	uint8_t prefix_len; /**< Number of valid leading bits. */
	uint8_t flags; /**< RTE_ICMP6_OPT_PREFIX_F_* */
	rte_be32_t valid_lifetime; /**< On-link validity (seconds). */
	rte_be32_t preferred_lifetime; /**< Address preference (seconds). */
	uint32_t __reserved;
	struct rte_ipv6_addr prefix; /**< IPv6 address prefix. */
} __rte_packed_end;

/** Redirected Header option payload (::RTE_ICMP6_OPT_REDIRECT). */
struct __rte_packed_begin rte_icmp6_opt_redirect {
	uint8_t __reserved[6];
} __rte_packed_end;

/** MTU option payload (::RTE_ICMP6_OPT_MTU). */
struct __rte_packed_begin rte_icmp6_opt_mtu {
	uint16_t __reserved;
	rte_be32_t mtu; /**< Recommended MTU for the link. */
} __rte_packed_end;

/**
 * Search for a specific NDP option in the option chain of an ICMPv6 message.
 *
 * Walks the TLV option chain starting at @p offset in @p mbuf, looking for an
 * option matching @p type. On success, returns the byte offset of the option
 * payload (right after the 2-byte rte_icmp6_opt header). The caller can then
 * use rte_pktmbuf_read() to access the option-specific data.
 *
 * @param mbuf
 *   The packet buffer containing the ICMPv6 message.
 * @param offset
 *   Byte offset in @p mbuf where the option chain begins (i.e. right after the
 *   type-specific ICMPv6 header).
 * @param type
 *   The option type to look for (RTE_ICMP6_OPT_*).
 * @return
 *   Byte offset of the option payload on success, or a negative value on
 *   error: -ENOENT if the option was not found, -EMSGSIZE if a malformed
 *   option was encountered.
 */
static inline int
rte_icmp6_get_opt(const struct rte_mbuf *mbuf, uint16_t offset, uint8_t type)
{
	const struct rte_icmp6_opt *opt;
	struct rte_icmp6_opt buf;

	while ((opt = rte_pktmbuf_read(mbuf, offset, sizeof(*opt), &buf)) != NULL) {
		if (opt->len == 0)
			return -EMSGSIZE;
		if (opt->type == type)
			return offset + sizeof(*opt);
		offset += opt->len * 8;
	}

	return -ENOENT;
}

/**
 * Extract a link-layer address from the NDP option chain.
 *
 * @param mbuf
 *   The packet buffer containing the ICMPv6 message.
 * @param offset
 *   Byte offset in @p mbuf where the option chain begins.
 * @param type
 *   ::RTE_ICMP6_OPT_SRC_LLADDR or ::RTE_ICMP6_OPT_TARGET_LLADDR.
 * @param[out] addr
 *   Where to store the extracted link-layer address.
 * @return
 *   0 on success, or a negative errno value (-ENOENT, -EMSGSIZE).
 */
static inline int
rte_icmp6_get_opt_lladdr(const struct rte_mbuf *mbuf, uint16_t offset, uint8_t type,
			 struct rte_ether_addr *addr)
{
	const struct rte_icmp6_opt_lladdr *ll;
	struct rte_icmp6_opt_lladdr buf;
	int off;

	off = rte_icmp6_get_opt(mbuf, offset, type);
	if (off < 0)
		return off;

	ll = rte_pktmbuf_read(mbuf, off, sizeof(*ll), &buf);
	if (ll == NULL)
		return -EMSGSIZE;

	*addr = ll->mac;

	return 0;
}

/**
 * Extract the MTU value from the NDP option chain.
 *
 * @param mbuf
 *   The packet buffer containing the ICMPv6 message.
 * @param offset
 *   Byte offset in @p mbuf where the option chain begins.
 * @param[out] mtu
 *   Where to store the extracted MTU value (network byte order).
 * @return
 *   0 on success, or a negative errno value (-ENOENT, -EMSGSIZE).
 */
static inline int
rte_icmp6_get_opt_mtu(const struct rte_mbuf *mbuf, uint16_t offset, rte_be32_t *mtu)
{
	const struct rte_icmp6_opt_mtu *m;
	struct rte_icmp6_opt_mtu buf;
	int off;

	off = rte_icmp6_get_opt(mbuf, offset, RTE_ICMP6_OPT_MTU);
	if (off < 0)
		return off;

	m = rte_pktmbuf_read(mbuf, off, sizeof(*m), &buf);
	if (m == NULL)
		return -EMSGSIZE;

	*mtu = m->mtu;

	return 0;
}

#endif /* _RTE_ICMP6_H_ */
