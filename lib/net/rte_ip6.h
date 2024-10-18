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

#include <rte_byteorder.h>
#include <rte_cksum.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Maximum IPv6 address size in bytes.
 */
#define RTE_IPV6_ADDR_SIZE 16

/**
 * Maximum IPv6 address size in bits.
 */
#define RTE_IPV6_MAX_DEPTH (RTE_IPV6_ADDR_SIZE * CHAR_BIT)

/**
 * IPv6 Address
 */
struct rte_ipv6_addr {
	uint8_t a[RTE_IPV6_ADDR_SIZE];
};

/**
 * Check if two IPv6 Addresses are equal.
 *
 * @param a
 *   The first address.
 * @param b
 *   The second address.
 * @return
 *   true if both addresses are identical.
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
 * @param[in] ip
 *   The address to mask.
 * @param[out] depth
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
 * @return
 *   @c true if the first @p depth bits of both addresses are identical.
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
 * @param mask
 *   The address mask.
 * @return
 *   The number of consecutive bits set to 1 starting from the beginning of the mask.
 */
static inline uint8_t
rte_ipv6_mask_depth(const struct rte_ipv6_addr *mask)
{
	uint8_t depth = 0;

	for (unsigned int i = 0; i < RTE_DIM(mask->a); i++) {
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

/**
 * Split a literal 16 bit unsigned integer into two bytes separated by a comma
 * according to the platform endianness.
 *
 * @param x
 *   A @c uint16_t literal value.
 * @return
 *   Two @c uint8_t literals separated by a coma.
 */
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
#define RTE_IPV6_U16_SPLIT(x) \
	(uint8_t)((uint16_t)(x) & UINT16_C(0xff)), \
	(uint8_t)(((uint16_t)(x) >> 8) & UINT16_C(0xff))
#else
#define RTE_IPV6_U16_SPLIT(x) \
	(uint8_t)(((uint16_t)(x) >> 8) & UINT16_C(0xff)), \
	(uint8_t)((uint16_t)(x) & UINT16_C(0xff))
#endif

/**
 * Shorthand to define a literal IPv6 address based on 16bit unsigned integers.
 *
 * @param a,b,c,d,e,f
 *   @c uint8_t literals that will be passed to RTE_IPV6_U16_SPLIT(x).
 * @return
 *   A literal @ref rte_ipv6_addr value suitable for static initialization.
 */
#define RTE_IPV6(a, b, c, d, e, f, g, h) \
	{{ \
		RTE_IPV6_U16_SPLIT(a), \
		RTE_IPV6_U16_SPLIT(b), \
		RTE_IPV6_U16_SPLIT(c), \
		RTE_IPV6_U16_SPLIT(d), \
		RTE_IPV6_U16_SPLIT(e), \
		RTE_IPV6_U16_SPLIT(f), \
		RTE_IPV6_U16_SPLIT(g), \
		RTE_IPV6_U16_SPLIT(h) \
	}}

/**
 * printf() format element for @ref rte_ipv6_addr structures.
 * To be used along with RTE_IPV6_ADDR_SPLIT(ip).
 */
#define RTE_IPV6_ADDR_FMT \
	"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"

/**
 * For use with #RTE_IPV6_ADDR_FMT. E.g.:
 *
 * @code
 * printf(RTE_IPV6_ADDR_FMT "\n", RTE_IPV6_ADDR_SPLIT(&ip));
 * @endcode
 *
 * @param ip
 *   A struct rte_ipv6_addr pointer.
 * @return
 *   A set of 16 @c uint8_t values separated by comas for use in printf().
 */
#define RTE_IPV6_ADDR_SPLIT(ip) \
	((uint8_t)(ip)->a[0]), \
	((uint8_t)(ip)->a[1]), \
	((uint8_t)(ip)->a[2]), \
	((uint8_t)(ip)->a[3]), \
	((uint8_t)(ip)->a[4]), \
	((uint8_t)(ip)->a[5]), \
	((uint8_t)(ip)->a[6]), \
	((uint8_t)(ip)->a[7]), \
	((uint8_t)(ip)->a[8]), \
	((uint8_t)(ip)->a[9]), \
	((uint8_t)(ip)->a[10]), \
	((uint8_t)(ip)->a[11]), \
	((uint8_t)(ip)->a[12]), \
	((uint8_t)(ip)->a[13]), \
	((uint8_t)(ip)->a[14]), \
	((uint8_t)(ip)->a[15])

/** Full IPv6 mask. NB: this is not a valid/routable IPv6 address. */
#define RTE_IPV6_MASK_FULL \
	RTE_IPV6(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)

/** Unspecified IPv6 address as defined in RFC 4291, section 2.5.2. */
#define RTE_IPV6_ADDR_UNSPEC RTE_IPV6(0, 0, 0, 0, 0, 0, 0, 0)

/**
 * Check if an IPv6 address is unspecified as defined in RFC 4291, section 2.5.2.
 *
 * @param ip
 *   The address to check.
 * @return
 *   @c true if the address is the unspecified address (all zeroes).
 */
static inline bool
rte_ipv6_addr_is_unspec(const struct rte_ipv6_addr *ip)
{
	const struct rte_ipv6_addr unspec = RTE_IPV6_ADDR_UNSPEC;
	return rte_ipv6_addr_eq(ip, &unspec);
}

/** Loopback IPv6 address as defined in RFC 4291, section 2.5.3. */
#define RTE_IPV6_ADDR_LOOPBACK RTE_IPV6(0, 0, 0, 0, 0, 0, 0, 1)

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
	if (ol_flags & (RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_UDP_SEG))
		psd_hdr.len = 0;
	else
		psd_hdr.len = ipv6_hdr->payload_len;

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
