.. SPDX-License-Identifier: BSD-3-Clause
   Copyright 2024 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 24.11
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      ninja -C build doc
      xdg-open build/doc/guides/html/rel_notes/release_24_11.html


New Features
------------

.. This section should contain new features added in this release.
   Sample format:

   * **Add a title in the past tense with a full stop.**

     Add a short 1-2 sentence description in the past tense.
     The description should be enough to allow someone scanning
     the release notes to understand the new feature.

     If the feature adds a lot of sub-features you can use a bullet list
     like this:

     * Added feature foo to do something.
     * Enhanced feature bar to do something else.

     Refer to the previous release notes for examples.

     Suggested order in release notes items:
     * Core libs (EAL, mempool, ring, mbuf, buses)
     * Device abstraction libs and PMDs (ordered alphabetically by vendor name)
       - ethdev (lib, PMDs)
       - cryptodev (lib, PMDs)
       - eventdev (lib, PMDs)
       - etc
     * Other libs
     * Apps, Examples, Tools (if significant)

     This section is a comment. Do not overwrite or remove it.
     Also, make sure to start the actual text at the margin.
     =======================================================

* **Added new bit manipulation API.**

  The support for bit-level operations on single 32- and 64-bit words in
  <rte_bitops.h> has been extended with semantically well-defined functions.

  * ``rte_bit_[test|set|clear|assign|flip]`` functions provide excellent
    performance (by avoiding restricting the compiler and CPU), but give
    no guarantees in regards to memory ordering or atomicity.

  * ``rte_bit_atomic_*`` provide atomic bit-level operations, including
    the possibility to specify memory ordering constraints.

  The new public API elements are polymorphic, using the _Generic-based
  macros (for C) and function overloading (in C++ translation units).

* **Extended service cores statistics.**

  Two new per-service counters are added to the service cores framework.

  * ``RTE_SERVICE_ATTR_IDLE_CALL_COUNT`` tracks the number of service function
    invocations where no actual work was performed.

  * ``RTE_SERVICE_ATTR_ERROR_CALL_COUNT`` tracks the number invocations
    resulting in an error.

  The new statistics are useful for debugging and profiling.

* **Hardened rte_malloc and related functions.**

  Added function attributes to ``rte_malloc`` and similar functions
  that can catch some obvious bugs at compile time (with GCC 11.0 or later).
  Examples: calling ``free`` on pointer that was allocated with ``rte_malloc``
  (and vice versa); freeing the same pointer twice in the same routine;
  freeing an object that was not created by allocation; etc.

* **Added cryptodev queue pair reset support.**

  A new API ``rte_cryptodev_queue_pair_reset`` is added
  to reset a particular queue pair of a device.

* **Added cryptodev asymmetric EdDSA support.**

  Added asymmetric EdDSA as referenced in `RFC 8032
  <https://datatracker.ietf.org/doc/html/rfc8032>`_.

* **Updated IPsec_MB crypto driver.**

  * Added support for SM3 algorithm.
  * Added support for SM3 HMAC algorithm.
  * Added support for SM4 CBC, SM4 ECB and SM4 CTR algorithms.

* **Updated openssl crypto driver.**

  * Added support for asymmetric crypto EdDSA algorithm.

* **Updated Marvell cnxk crypto driver.**

  * Added support for asymmetric crypto EdDSA algorithm.

* **Added stateless IPsec processing.**

  New functions were added to enable
  providing sequence number to be used for the IPsec operation.

* **Added event device pre-scheduling support.**

  Added support for pre-scheduling of events to event ports
  to improve scheduling performance and latency.

  * Added ``rte_event_dev_config::preschedule_type``
    to configure the device level pre-scheduling type.

  * Added ``rte_event_port_preschedule_modify``
    to modify pre-scheduling type on a given event port.

  * Added ``rte_event_port_preschedule``
    to allow applications provide explicit pre-schedule hints to event ports.

* **Updated event device library for independent enqueue feature.**

  Added support for independent enqueue feature.
  With this feature eventdev supports enqueue in any order
  or specifically in a different order than dequeue.
  The feature is intended for eventdevs supporting burst mode.
  Applications should use ``RTE_EVENT_PORT_CFG_INDEPENDENT_ENQ`` to enable
  the feature if the capability ``RTE_EVENT_DEV_CAP_INDEPENDENT_ENQ`` exists.

* **Updated DLB2 event driver.**

  * Added independent enqueue feature.

* **Updated DSW event driver.**

  * Added independent enqueue feature.


Removed Items
-------------

.. This section should contain removed items in this release. Sample format:

   * Add a short 1-2 sentence description of the removed item
     in the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================


API Changes
-----------

.. This section should contain API changes. Sample format:

   * sample: Add a short 1-2 sentence description of the API change
     which was announced in the previous releases and made in this release.
     Start with a scope label like "ethdev:".
     Use fixed width quotes for ``function_names`` or ``struct_names``.
     Use the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================

* net: IPv6 related symbols were moved from ``<rte_ip.h>`` to the new ``<rte_ip6.h>`` header.
* net: The ``rte_ipv6_hdr`` structure was modified to use ``struct rte_ipv6_addr`` instead of ``uint8_t[16]`` fields.
* rib6,fib6,lpm6: All public API functions were modified to use ``struct rte_ipv6_addr`` instead of ``uint8_t[16]`` parameters.
* cmdline: ``cmdline_ipaddr_t`` was modified to use ``struct rte_ipv6_addr`` instead of ``in6_addr``.
* node: ``rte_node_ip6_route_add()`` was modified to use a ``struct rte_ipv6_addr`` instead of ``uint8_t[16]`` parameter.
* pipeline: ``rte_table_action_ipv6_header`` and ``rte_table_action_nat_params`` were modified to use ``struct rte_ipv6_addr`` instead of ``uint8_t[16]`` fields.
* pipeline: ``rte_swx_ipsec_sa_encap_params`` was modified to use ``rte_ipv6_addr`` instead of ``in6_addr``.
* ipsec: ``rte_ipsec_sadv6_key`` was modified to use ``struct rte_ipv6_addr`` instead of ``uint8_t[16]`` fields.
* security: ``rte_security_ipsec_tunnel_param`` was modified to use ``rte_ipv6_addr`` instead of ``in6_addr``.

ABI Changes
-----------

.. This section should contain ABI changes. Sample format:

   * sample: Add a short 1-2 sentence description of the ABI change
     which was announced in the previous releases and made in this release.
     Start with a scope label like "ethdev:".
     Use fixed width quotes for ``function_names`` or ``struct_names``.
     Use the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================

* eal: The maximum number of file descriptors that can be passed to a secondary process
  has been increased from 8 to 253 (which is the maximum possible with Unix domain socket).
  This allows for more queues when using software devices such as TAP and XDP.

* cryptodev: The queue pair configuration structure ``rte_cryptodev_qp_conf``
  is updated to have a new parameter to set priority of that particular queue pair.

* cryptodev: The list end enumerators ``RTE_CRYPTO_ASYM_XFORM_TYPE_LIST_END``
  and ``RTE_CRYPTO_RSA_PADDING_TYPE_LIST_END`` are removed
  to allow subsequent addition of new asymmetric algorithms and RSA padding types.

* cryptodev: The enum ``rte_crypto_asym_xform_type`` and struct ``rte_crypto_asym_op``
  are updated to include new values to support EdDSA.

* cryptodev: The ``rte_crypto_rsa_xform`` struct member to hold private key
  in either exponent or quintuple format is changed from union to struct data type.
  This change is to support ASN.1 syntax (RFC 3447 Appendix A.1.2).

* cryptodev: The padding struct ``rte_crypto_rsa_padding`` is moved
  from ``rte_crypto_rsa_op_param`` to ``rte_crypto_rsa_xform``
  as the padding information is part of session creation
  instead of per packet crypto operation.
  This change is required to support virtio-crypto specifications.

* eventdev: Added ``preschedule_type`` field to ``rte_event_dev_config`` structure.


Known Issues
------------

.. This section should contain new known issues in this release. Sample format:

   * **Add title in present tense with full stop.**

     Add a short 1-2 sentence description of the known issue
     in the present tense. Add information on any known workarounds.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================


Tested Platforms
----------------

.. This section should contain a list of platforms that were tested
   with this release.

   The format is:

   * <vendor> platform with <vendor> <type of devices> combinations

     * List of CPU
     * List of OS
     * List of devices
     * Other relevant details...

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =======================================================
