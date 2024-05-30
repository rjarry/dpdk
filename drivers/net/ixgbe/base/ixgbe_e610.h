/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Intel Corporation
 */

#ifndef _IXGBE_E610_H_
#define _IXGBE_E610_H_

#include "ixgbe_type.h"

void ixgbe_init_aci(struct ixgbe_hw *hw);
void ixgbe_shutdown_aci(struct ixgbe_hw *hw);

s32 ixgbe_aci_send_cmd(struct ixgbe_hw *hw, struct ixgbe_aci_desc *desc,
		       void *buf, u16 buf_size);
bool ixgbe_aci_check_event_pending(struct ixgbe_hw *hw);
s32 ixgbe_aci_get_event(struct ixgbe_hw *hw, struct ixgbe_aci_event *e,
			bool *pending);

void ixgbe_fill_dflt_direct_cmd_desc(struct ixgbe_aci_desc *desc, u16 opcode);

s32 ixgbe_acquire_res(struct ixgbe_hw *hw, enum ixgbe_aci_res_ids res,
		      enum ixgbe_aci_res_access_type access, u32 timeout);
void ixgbe_release_res(struct ixgbe_hw *hw, enum ixgbe_aci_res_ids res);
s32 ixgbe_aci_list_caps(struct ixgbe_hw *hw, void *buf, u16 buf_size,
			u32 *cap_count, enum ixgbe_aci_opc opc);
s32 ixgbe_discover_dev_caps(struct ixgbe_hw *hw,
			    struct ixgbe_hw_dev_caps *dev_caps);
s32 ixgbe_discover_func_caps(struct ixgbe_hw* hw,
			     struct ixgbe_hw_func_caps* func_caps);
s32 ixgbe_get_caps(struct ixgbe_hw *hw);
s32 ixgbe_aci_disable_rxen(struct ixgbe_hw *hw);
s32 ixgbe_aci_get_phy_caps(struct ixgbe_hw *hw, bool qual_mods, u8 report_mode,
			   struct ixgbe_aci_cmd_get_phy_caps_data *pcaps);
bool ixgbe_phy_caps_equals_cfg(struct ixgbe_aci_cmd_get_phy_caps_data *caps,
			       struct ixgbe_aci_cmd_set_phy_cfg_data *cfg);
void ixgbe_copy_phy_caps_to_cfg(struct ixgbe_aci_cmd_get_phy_caps_data *caps,
				struct ixgbe_aci_cmd_set_phy_cfg_data *cfg);
s32 ixgbe_aci_get_internal_data(struct ixgbe_hw *hw, u16 cluster_id,
				u16 table_id, u32 start, void *buf,
				u16 buf_size, u16 *ret_buf_size,
				u16 *ret_next_cluster, u16 *ret_next_table,
				u32 *ret_next_index);

#endif /* _IXGBE_E610_H_ */