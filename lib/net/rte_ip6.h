/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 1982, 1986, 1990, 1993
 *      The Regents of the University of California.
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright(c) 2014 6WIND S.A.
 * All rights reserved.
 */

#ifndef _RTE_IP6_H_
#define _RTE_IP6_H_

/**
 * @file
 *
 * IPv6-related defines
 */

#include <stdint.h>
#include <string.h>

#ifdef RTE_EXEC_ENV_WINDOWS
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#endif

#include <rte_ether.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_cksum.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RTE_IPV6_ADDR_SIZE 16
#define RTE_IPV6_MAX_DEPTH 128

/**
 * IPv6 Address
 */
struct rte_ipv6_addr {
	unsigned char a[RTE_IPV6_ADDR_SIZE];
};

/** Shorthand to initialize IPv6 address values */
#define RTE_IPV6_ADDR(...) ((struct rte_ipv6_addr){.a = {__VA_ARGS__}})

/**
 * Copy an IPv6 address into another one.
 *
 * @param dst
 *   The address into which to copy data.
 * @param src
 *   The address from which to copy.
 */
static inline void
rte_ipv6_addr_cpy(struct rte_ipv6_addr *dst, const struct rte_ipv6_addr *src)
{
	rte_memcpy(dst, src, sizeof(*dst));
}

/**
 * Check if two IPv6 Addresses are equal.
 */
static inline bool
rte_ipv6_addr_eq(const struct rte_ipv6_addr *a, const struct rte_ipv6_addr *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

/**
 * Mask an IPv6 address using the specified depth.
 *
 * Leave untouched one bit per unit in the depth variable and set the rest to 0.
 *
 * @param ip
 *   The address to mask.
 * @param depth
 *   All bits starting from this bit number will be set to zero.
 */
static inline void
rte_ipv6_addr_mask(struct rte_ipv6_addr *ip, uint8_t depth)
{
	if (depth < RTE_IPV6_MAX_DEPTH) {
		uint8_t d = depth / 8;
		uint8_t mask = ~(UINT8_MAX >> (depth % 8));
		ip->a[d] &= mask;
		d++;
		memset(&ip->a[d], 0, sizeof(*ip) - d);
	}
}

/**
 * Check if two IPv6 addresses belong to the same network prefix.
 *
 * @param a
 *  The first address or network.
 * @param b
 *  The second address or network.
 * @param depth
 *  The network prefix length.
 */
static inline bool
rte_ipv6_addr_eq_prefix(const struct rte_ipv6_addr *a, const struct rte_ipv6_addr *b, uint8_t depth)
{
	if (depth < RTE_IPV6_MAX_DEPTH) {
		uint8_t d = depth / 8;
		uint8_t mask = ~(UINT8_MAX >> (depth % 8));

		if ((a->a[d] ^ b->a[d]) & mask)
			return false;

		return memcmp(a, b, d) == 0;
	}
	return rte_ipv6_addr_eq(a, b);
}

/**
 * Get the depth of a given IPv6 address mask.
 *
 * This function does not handle masks with "holes" and will return the number
 * of consecurive bits set to 1 starting from the beginning of the mask.
 *
 * @param mask
 *   The address mask.
 */
static inline uint8_t
rte_ipv6_mask_depth(const struct rte_ipv6_addr *mask)
{
	uint8_t depth = 0;

	for (int i = 0; i < RTE_IPV6_ADDR_SIZE; i++) {
		uint8_t m = mask->a[i];
		if (m == 0xff) {
			depth += 8;
		} else {
			while (m & 0x80) {
				m <<= 1;
				depth++;
			}
			break;
		}
	}

	return depth;
}

#define RTE_IPV6_ADDR_UNSPEC RTE_IPV6_ADDR(0)

/**
 * Check if an IPv6 address is unspecified as defined in RFC 4291, section 2.5.2.
 */
static inline bool
rte_ipv6_addr_is_unspec(const struct rte_ipv6_addr *ip)
{
	struct rte_ipv6_addr unspec = RTE_IPV6_ADDR_UNSPEC;
	return rte_ipv6_addr_eq(ip, &unspec);
}

/** Loopback address as defined in RFC 4291, section 2.7.1. */
#define RTE_IPV6_ADDR_LOOPBACK RTE_IPV6_ADDR(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)

/**
 * Check if an IPv6 address is the loopback address as defined in RFC 4291,
 * section 2.5.3.
 */
static inline bool
rte_ipv6_addr_is_loopback(const struct rte_ipv6_addr *ip)
{
	struct rte_ipv6_addr loopback = RTE_IPV6_ADDR_LOOPBACK;
	return rte_ipv6_addr_eq(ip, &loopback);
}

/**
 * Check if an IPv6 address is link-local as defined in RFC 4291, section 2.5.6.
 */
static inline bool
rte_ipv6_addr_is_linklocal(const struct rte_ipv6_addr *ip)
{
	return ip->a[0] == 0xfe && (ip->a[1] & 0xc0) == 0x80;
}

/**
 * Check if an IPv6 address is site-local as defined in RFC 4291, section 2.5.7.
 */
static inline bool
rte_ipv6_addr_is_sitelocal(const struct rte_ipv6_addr *ip)
{
	return ip->a[0] == 0xfe && (ip->a[1] & 0xc0) == 0xc0;
}

/**
 * Check if an IPv6 address is an IPv4-compatible address as defined in RFC 4291,
 * section 2.5.5.1.
 */
static inline bool
rte_ipv6_addr_is_v4compat(const struct rte_ipv6_addr *ip)
{
	const rte_be32_t *a32 = (const rte_be32_t *)ip;
	return a32[0] == 0 && a32[1] == 0 && a32[2] == 0 && a32[3] != 0 && a32[3] != RTE_BE32(1);
}

/**
 * Check if an IPv6 address is an IPv4-mapped address as defined in RFC 4291,
 * section 2.5.5.2.
 */
static inline bool
rte_ipv6_addr_is_v4mapped(const struct rte_ipv6_addr *ip)
{
	const rte_be32_t *a32 = (const rte_be32_t *)ip;
	return a32[0] == 0 && a32[1] == 0 && a32[2] == RTE_BE32(0x0000ffff);
}

/**
 * IPv6 multicast scope values as defined in RFC 4291, section 2.7.
 */
typedef enum {
	RTE_IPV6_MC_SCOPE_RESERVED = 0x00,
	RTE_IPV6_MC_SCOPE_IFACELOCAL = 0x01,
	RTE_IPV6_MC_SCOPE_LINKLOCAL = 0x02,
	RTE_IPV6_MC_SCOPE_SITELOCAL = 0x05,
	RTE_IPV6_MC_SCOPE_ORGLOCAL = 0x08,
	RTE_IPV6_MC_SCOPE_GLOBAL = 0x0e,
} __rte_packed rte_ipv6_mc_scope_t;

/**
 * Extract the IPv6 multicast scope value as defined in RFC 4291, section 2.7.
 */
static inline rte_ipv6_mc_scope_t
rte_ipv6_mc_scope(const struct rte_ipv6_addr *ip)
{
	return (rte_ipv6_mc_scope_t)(ip->a[1] & 0x0f);
}

/**
 * Check if an IPv6 address is multicast as defined in RFC 4291, section 2.7.
 */
static inline bool
rte_ipv6_addr_is_mcast(const struct rte_ipv6_addr *ip)
{
	return ip->a[0] == 0xff;
}

/** Well known multicast addresses as defined in RFC 4291, section 2.7.1. */
#define RTE_IPV6_ADDR_ALLNODES_IFACE_LOCAL \
	RTE_IPV6_ADDR(0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
#define RTE_IPV6_ADDR_ALLNODES_LINK_LOCAL \
	RTE_IPV6_ADDR(0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
#define RTE_IPV6_ADDR_ALLROUTERS_IFACE_LOCAL \
	RTE_IPV6_ADDR(0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)
#define RTE_IPV6_ADDR_ALLROUTERS_LINK_LOCAL \
	RTE_IPV6_ADDR(0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)
#define RTE_IPV6_ADDR_ALLROUTERS_SITE_LOCAL \
	RTE_IPV6_ADDR(0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)

/**
 * Generate a link-local IPv6 address from an ethernet address as specified in
 * RFC 2464, section 5.
 */
static inline void
rte_ipv6_llocal_from_ethernet(struct rte_ipv6_addr *ip, const struct rte_ether_addr *mac)
{
	ip->a[0] = 0xfe;
	ip->a[1] = 0x80;
	memset(&ip->a[2], 0, 6);
	ip->a[8] = mac->addr_bytes[0];
	ip->a[9] = mac->addr_bytes[1];
	ip->a[10] = mac->addr_bytes[2];
	ip->a[11] = 0xff;
	ip->a[12] = 0xfe;
	ip->a[13] = mac->addr_bytes[3];
	ip->a[14] = mac->addr_bytes[4];
	ip->a[15] = mac->addr_bytes[5];
}

/**
 * Convert a unicast or anycast IPv6 address to a solicited-node multicast
 * address as defined in RFC 4291, section 2.7.1.
 */
static inline void
rte_ipv6_solnode_from_addr(struct rte_ipv6_addr *sol, const struct rte_ipv6_addr *ip)
{
	sol->a[0] = 0xff;
	sol->a[1] = 0x02;
	memset(&sol->a[2], 0, 9);
	sol->a[11] = 0x01;
	sol->a[12] = 0xff;
	sol->a[13] = ip->a[13];
	sol->a[14] = ip->a[14];
	sol->a[15] = ip->a[15];
}

/**
 * Generate a multicast ethernet address from a multicast IPv6 address as defined
 * in RFC 2464, section 7.
 */
static inline void
rte_ether_mcast_from_ipv6(struct rte_ether_addr *mac, const struct rte_ipv6_addr *ip)
{
	mac->addr_bytes[0] = 0x33;
	mac->addr_bytes[1] = 0x33;
	mac->addr_bytes[2] = ip->a[12];
	mac->addr_bytes[3] = ip->a[13];
	mac->addr_bytes[4] = ip->a[14];
	mac->addr_bytes[5] = ip->a[15];
}

/**
 * IPv6 Header
 */
struct rte_ipv6_hdr {
	rte_be32_t vtc_flow;	/**< IP version, traffic class & flow label. */
	rte_be16_t payload_len;	/**< IP payload size, including ext. headers */
	uint8_t  proto;		/**< Protocol, next header. */
	uint8_t  hop_limits;	/**< Hop limits. */
	struct rte_ipv6_addr src_addr;	/**< IP address of source host. */
	struct rte_ipv6_addr dst_addr;	/**< IP address of destination host(s). */
} __rte_packed;

/* IPv6 routing extension type definition. */
#define RTE_IPV6_SRCRT_TYPE_4 4

/**
 * IPv6 Routing Extension Header
 */
struct rte_ipv6_routing_ext {
	uint8_t next_hdr;			/**< Protocol, next header. */
	uint8_t hdr_len;			/**< Header length. */
	uint8_t type;				/**< Extension header type. */
	uint8_t segments_left;			/**< Valid segments number. */
	__extension__
	union {
		rte_be32_t flags;		/**< Packet control data per type. */
		struct {
			uint8_t last_entry;	/**< The last_entry field of SRH */
			uint8_t flag;		/**< Packet flag. */
			rte_be16_t tag;		/**< Packet tag. */
		};
	};
	/* Next are 128-bit IPv6 address fields to describe segments. */
} __rte_packed;

/* IPv6 vtc_flow: IPv / TC / flow_label */
#define RTE_IPV6_HDR_FL_SHIFT 0
#define RTE_IPV6_HDR_TC_SHIFT 20
#define RTE_IPV6_HDR_FL_MASK	((1u << RTE_IPV6_HDR_TC_SHIFT) - 1)
#define RTE_IPV6_HDR_TC_MASK	(0xff << RTE_IPV6_HDR_TC_SHIFT)
#define RTE_IPV6_HDR_DSCP_MASK	(0xfc << RTE_IPV6_HDR_TC_SHIFT)
#define RTE_IPV6_HDR_ECN_MASK	(0x03 << RTE_IPV6_HDR_TC_SHIFT)
#define RTE_IPV6_HDR_ECN_CE	RTE_IPV6_HDR_ECN_MASK

#define RTE_IPV6_MIN_MTU 1280 /**< Minimum MTU for IPv6, see RFC 8200. */

/**
 * Process the pseudo-header checksum of an IPv6 header.
 *
 * Depending on the ol_flags, the pseudo-header checksum expected by the
 * drivers is not the same. For instance, when TSO is enabled, the IPv6
 * payload length must not be included in the packet.
 *
 * When ol_flags is 0, it computes the standard pseudo-header checksum.
 *
 * @param ipv6_hdr
 *   The pointer to the contiguous IPv6 header.
 * @param ol_flags
 *   The ol_flags of the associated mbuf.
 * @return
 *   The non-complemented checksum to set in the L4 header.
 */
static inline uint16_t
rte_ipv6_phdr_cksum(const struct rte_ipv6_hdr *ipv6_hdr, uint64_t ol_flags)
{
	uint32_t sum;
	struct {
		rte_be32_t len;   /* L4 length. */
		rte_be32_t proto; /* L4 protocol - top 3 bytes must be zero */
	} psd_hdr;

	psd_hdr.proto = (uint32_t)(ipv6_hdr->proto << 24);
	if (ol_flags & (RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_UDP_SEG)) {
		psd_hdr.len = 0;
	} else {
		psd_hdr.len = ipv6_hdr->payload_len;
	}

	sum = __rte_raw_cksum(&ipv6_hdr->src_addr,
		sizeof(ipv6_hdr->src_addr) + sizeof(ipv6_hdr->dst_addr),
		0);
	sum = __rte_raw_cksum(&psd_hdr, sizeof(psd_hdr), sum);
	return __rte_raw_cksum_reduce(sum);
}

/**
 * @internal Calculate the non-complemented IPv6 L4 checksum
 */
static inline uint16_t
__rte_ipv6_udptcp_cksum(const struct rte_ipv6_hdr *ipv6_hdr, const void *l4_hdr)
{
	uint32_t cksum;
	uint32_t l4_len;

	l4_len = rte_be_to_cpu_16(ipv6_hdr->payload_len);

	cksum = rte_raw_cksum(l4_hdr, l4_len);
	cksum += rte_ipv6_phdr_cksum(ipv6_hdr, 0);

	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);

	return (uint16_t)cksum;
}

/**
 * Process the IPv6 UDP or TCP checksum.
 *
 * The IPv6 header must not be followed by extension headers. The layer 4
 * checksum must be set to 0 in the L4 header by the caller.
 *
 * @param ipv6_hdr
 *   The pointer to the contiguous IPv6 header.
 * @param l4_hdr
 *   The pointer to the beginning of the L4 header.
 * @return
 *   The complemented checksum to set in the L4 header.
 */
static inline uint16_t
rte_ipv6_udptcp_cksum(const struct rte_ipv6_hdr *ipv6_hdr, const void *l4_hdr)
{
	uint16_t cksum = __rte_ipv6_udptcp_cksum(ipv6_hdr, l4_hdr);

	cksum = ~cksum;

	/*
	 * Per RFC 768: If the computed checksum is zero for UDP,
	 * it is transmitted as all ones
	 * (the equivalent in one's complement arithmetic).
	 */
	if (cksum == 0 && ipv6_hdr->proto == IPPROTO_UDP)
		cksum = 0xffff;

	return cksum;
}

/**
 * @internal Calculate the non-complemented IPv6 L4 checksum of a packet
 */
static inline uint16_t
__rte_ipv6_udptcp_cksum_mbuf(const struct rte_mbuf *m,
			     const struct rte_ipv6_hdr *ipv6_hdr,
			     uint16_t l4_off)
{
	uint16_t raw_cksum;
	uint32_t cksum;

	if (unlikely(l4_off > m->pkt_len))
		return 0; /* invalid params, return a dummy value */

	if (rte_raw_cksum_mbuf(m, l4_off, rte_be_to_cpu_16(ipv6_hdr->payload_len), &raw_cksum))
		return 0;

	cksum = raw_cksum + rte_ipv6_phdr_cksum(ipv6_hdr, 0);

	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);

	return (uint16_t)cksum;
}

/**
 * Process the IPv6 UDP or TCP checksum of a packet.
 *
 * The IPv6 header must not be followed by extension headers. The layer 4
 * checksum must be set to 0 in the L4 header by the caller.
 *
 * @param m
 *   The pointer to the mbuf.
 * @param ipv6_hdr
 *   The pointer to the contiguous IPv6 header.
 * @param l4_off
 *   The offset in bytes to start L4 checksum.
 * @return
 *   The complemented checksum to set in the L4 header.
 */
static inline uint16_t
rte_ipv6_udptcp_cksum_mbuf(const struct rte_mbuf *m,
			   const struct rte_ipv6_hdr *ipv6_hdr, uint16_t l4_off)
{
	uint16_t cksum = __rte_ipv6_udptcp_cksum_mbuf(m, ipv6_hdr, l4_off);

	cksum = ~cksum;

	/*
	 * Per RFC 768: If the computed checksum is zero for UDP,
	 * it is transmitted as all ones
	 * (the equivalent in one's complement arithmetic).
	 */
	if (cksum == 0 && ipv6_hdr->proto == IPPROTO_UDP)
		cksum = 0xffff;

	return cksum;
}

/**
 * Validate the IPv6 UDP or TCP checksum.
 *
 * In case of UDP, the caller must first check if udp_hdr->dgram_cksum is 0:
 * this is either invalid or means no checksum in some situations. See 8.1
 * (Upper-Layer Checksums) in RFC 8200.
 *
 * @param ipv6_hdr
 *   The pointer to the contiguous IPv6 header.
 * @param l4_hdr
 *   The pointer to the beginning of the L4 header.
 * @return
 *   Return 0 if the checksum is correct, else -1.
 */
static inline int
rte_ipv6_udptcp_cksum_verify(const struct rte_ipv6_hdr *ipv6_hdr,
			     const void *l4_hdr)
{
	uint16_t cksum = __rte_ipv6_udptcp_cksum(ipv6_hdr, l4_hdr);

	if (cksum != 0xffff)
		return -1;

	return 0;
}

/**
 * Validate the IPv6 UDP or TCP checksum of a packet.
 *
 * In case of UDP, the caller must first check if udp_hdr->dgram_cksum is 0:
 * this is either invalid or means no checksum in some situations. See 8.1
 * (Upper-Layer Checksums) in RFC 8200.
 *
 * @param m
 *   The pointer to the mbuf.
 * @param ipv6_hdr
 *   The pointer to the contiguous IPv6 header.
 * @param l4_off
 *   The offset in bytes to start L4 checksum.
 * @return
 *   Return 0 if the checksum is correct, else -1.
 */
static inline int
rte_ipv6_udptcp_cksum_mbuf_verify(const struct rte_mbuf *m,
				  const struct rte_ipv6_hdr *ipv6_hdr,
				  uint16_t l4_off)
{
	uint16_t cksum = __rte_ipv6_udptcp_cksum_mbuf(m, ipv6_hdr, l4_off);

	if (cksum != 0xffff)
		return -1;

	return 0;
}

/** IPv6 fragment extension header. */
#define	RTE_IPV6_EHDR_MF_SHIFT	0
#define	RTE_IPV6_EHDR_MF_MASK	1
#define	RTE_IPV6_EHDR_FO_SHIFT	3
#define	RTE_IPV6_EHDR_FO_MASK	(~((1 << RTE_IPV6_EHDR_FO_SHIFT) - 1))
#define	RTE_IPV6_EHDR_FO_ALIGN	(1 << RTE_IPV6_EHDR_FO_SHIFT)

#define RTE_IPV6_FRAG_USED_MASK	(RTE_IPV6_EHDR_MF_MASK | RTE_IPV6_EHDR_FO_MASK)

#define RTE_IPV6_GET_MF(x)	((x) & RTE_IPV6_EHDR_MF_MASK)
#define RTE_IPV6_GET_FO(x)	((x) >> RTE_IPV6_EHDR_FO_SHIFT)

#define RTE_IPV6_SET_FRAG_DATA(fo, mf)	\
	(((fo) & RTE_IPV6_EHDR_FO_MASK) | ((mf) & RTE_IPV6_EHDR_MF_MASK))

struct rte_ipv6_fragment_ext {
	uint8_t next_header;	/**< Next header type */
	uint8_t reserved;	/**< Reserved */
	rte_be16_t frag_data;	/**< All fragmentation data */
	rte_be32_t id;		/**< Packet ID */
} __rte_packed;

/* IPv6 fragment extension header size */
#define RTE_IPV6_FRAG_HDR_SIZE	sizeof(struct rte_ipv6_fragment_ext)

/**
 * Parse next IPv6 header extension
 *
 * This function checks if proto number is an IPv6 extensions and parses its
 * data if so, providing information on next header and extension length.
 *
 * @param p
 *   Pointer to an extension raw data.
 * @param proto
 *   Protocol number extracted from the "next header" field from
 *   the IPv6 header or the previous extension.
 * @param ext_len
 *   Extension data length.
 * @return
 *   next protocol number if proto is an IPv6 extension, -EINVAL otherwise
 */
static inline int
rte_ipv6_get_next_ext(const uint8_t *p, int proto, size_t *ext_len)
{
	int next_proto;

	switch (proto) {
	case IPPROTO_AH:
		next_proto = *p++;
		*ext_len = (*p + 2) * sizeof(uint32_t);
		break;

	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_DSTOPTS:
		next_proto = *p++;
		*ext_len = (*p + 1) * sizeof(uint64_t);
		break;

	case IPPROTO_FRAGMENT:
		next_proto = *p;
		*ext_len = RTE_IPV6_FRAG_HDR_SIZE;
		break;

	default:
		return -EINVAL;
	}

	return next_proto;
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_IP6_H_ */
