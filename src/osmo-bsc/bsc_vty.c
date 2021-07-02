/* OsmoBSC interface to quagga VTY */
/* (C) 2009-2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/tdef_vty.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm0502.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/gsm23236.h>
#include <osmocom/core/sockaddr_str.h>

#include <arpa/inet.h>

#include <osmocom/core/byteswap.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/socket.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/bsc/abis_nm.h>
#include <osmocom/bsc/abis_om2000.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/abis_nm.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/meas_rep.h>
#include <osmocom/bsc/vty.h>
#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/bsc/system_information.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/ipaccess.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/bsc_msc_data.h>
#include <osmocom/bsc/osmo_bsc_rf.h>
#include <osmocom/bsc/pcu_if.h>
#include <osmocom/bsc/handover_fsm.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/handover_vty.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/acc.h>
#include <osmocom/bsc/meas_feed.h>
#include <osmocom/bsc/neighbor_ident.h>
#include <osmocom/bsc/handover.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/lchan_select.h>
#include <osmocom/bsc/smscb.h>
#include <osmocom/bsc/osmo_bsc.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/mgcp_client/mgcp_client_endpoint_fsm.h>

#include <inttypes.h>

#include "../../bscconfig.h"

#define X(x) (1 << x)

#define BTS_NR_STR "BTS Number\n"
#define TRX_NR_STR "TRX Number\n"
#define TS_NR_STR "Timeslot Number\n"
#define SS_NR_STR "Sub-slot Number\n"
#define LCHAN_NR_STR "Logical Channel Number\n"
#define BTS_TRX_STR BTS_NR_STR TRX_NR_STR
#define BTS_TRX_TS_STR BTS_TRX_STR TS_NR_STR
#define BTS_TRX_TS_LCHAN_STR BTS_TRX_TS_STR LCHAN_NR_STR
#define BTS_NR_TRX_TS_STR2 \
	"BTS for manual command\n" BTS_NR_STR \
	"TRX for manual command\n" TRX_NR_STR \
	"Timeslot for manual command\n" TS_NR_STR
#define BTS_NR_TRX_TS_SS_STR2 \
	BTS_NR_TRX_TS_STR2 \
	"Sub-slot for manual command\n" SS_NR_STR

/* FIXME: this should go to some common file */
static const struct value_string gprs_ns_timer_strs[] = {
	{ 0, "tns-block" },
	{ 1, "tns-block-retries" },
	{ 2, "tns-reset" },
	{ 3, "tns-reset-retries" },
	{ 4, "tns-test" },
	{ 5, "tns-alive" },
	{ 6, "tns-alive-retries" },
	{ 0, NULL }
};

static const struct value_string gprs_bssgp_cfg_strs[] = {
	{ 0,	"blocking-timer" },
	{ 1,	"blocking-retries" },
	{ 2,	"unblocking-retries" },
	{ 3,	"reset-timer" },
	{ 4,	"reset-retries" },
	{ 5,	"suspend-timer" },
	{ 6,	"suspend-retries" },
	{ 7,	"resume-timer" },
	{ 8,	"resume-retries" },
	{ 9,	"capability-update-timer" },
	{ 10,	"capability-update-retries" },
	{ 0,	NULL }
};

static const struct value_string bts_neigh_mode_strs[] = {
	{ NL_MODE_AUTOMATIC, "automatic" },
	{ NL_MODE_MANUAL, "manual" },
	{ NL_MODE_MANUAL_SI5SEP, "manual-si5" },
	{ 0, NULL }
};

const struct value_string bts_loc_fix_names[] = {
	{ BTS_LOC_FIX_INVALID,	"invalid" },
	{ BTS_LOC_FIX_2D,	"fix2d" },
	{ BTS_LOC_FIX_3D,	"fix3d" },
	{ 0, NULL }
};

static struct cmd_node net_node = {
	GSMNET_NODE,
	"%s(config-net)# ",
	1,
};

static struct cmd_node bts_node = {
	BTS_NODE,
	"%s(config-net-bts)# ",
	1,
};

static struct cmd_node power_ctrl_node = {
	POWER_CTRL_NODE,
	"%s(config-power-ctrl)# ",
	1,
};

static struct cmd_node trx_node = {
	TRX_NODE,
	"%s(config-net-bts-trx)# ",
	1,
};

static struct cmd_node ts_node = {
	TS_NODE,
	"%s(config-net-bts-trx-ts)# ",
	1,
};

static struct gsm_network *vty_global_gsm_network = NULL;

struct gsm_network *gsmnet_from_vty(struct vty *v)
{
	/* It can't hurt to force callers to continue to pass the vty instance
	 * to this function, in case we'd like to retrieve the global
	 * gsm_network instance from the vty at some point in the future. But
	 * until then, just return the global pointer, which should have been
	 * initialized by common_cs_vty_init().
	 */
	OSMO_ASSERT(vty_global_gsm_network);
	return vty_global_gsm_network;
}

static int dummy_config_write(struct vty *v)
{
	return CMD_SUCCESS;
}

static void net_dump_nmstate(struct vty *vty, struct gsm_nm_state *nms)
{
	vty_out(vty,"Oper '%s', Admin '%s', Avail '%s'%s",
		abis_nm_opstate_name(nms->operational),
		get_value_string(abis_nm_adm_state_names, nms->administrative),
		abis_nm_avail_name(nms->availability), VTY_NEWLINE);
}

static void dump_pchan_load_vty(struct vty *vty, char *prefix,
				const struct pchan_load *pl)
{
	int i;
	int dumped = 0;

	for (i = 0; i < ARRAY_SIZE(pl->pchan); i++) {
		const struct load_counter *lc = &pl->pchan[i];
		unsigned int percent;

		if (lc->total == 0)
			continue;

		percent = (lc->used * 100) / lc->total;

		vty_out(vty, "%s%20s: %3u%% (%u/%u)%s", prefix,
			gsm_pchan_name(i), percent, lc->used, lc->total,
			VTY_NEWLINE);
		dumped ++;
	}
	if (!dumped)
		vty_out(vty, "%s(none)%s", prefix, VTY_NEWLINE);
}

static void net_dump_vty(struct vty *vty, struct gsm_network *net)
{
	struct pchan_load pl;
	int i;

	vty_out(vty, "BSC is on MCC-MNC %s and has %u BTS%s",
		osmo_plmn_name(&net->plmn), net->num_bts, VTY_NEWLINE);
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "  Encryption:");
	for (i = 0; i < 8; i++) {
		if (net->a5_encryption_mask & (1 << i))
			vty_out(vty, " A5/%u", i);
	}
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "  NECI (TCH/H): %u%s", net->neci,
		VTY_NEWLINE);
	vty_out(vty, "  Use TCH for Paging any: %d%s", net->pag_any_tch,
		VTY_NEWLINE);

	{
		struct gsm_bts *bts;
		unsigned int ho_active_count = 0;
		unsigned int ho_inactive_count = 0;

		llist_for_each_entry(bts, &net->bts_list, list) {
			if (ho_get_ho_active(bts->ho))
				ho_active_count ++;
			else
				ho_inactive_count ++;
		}

		if (ho_active_count && ho_inactive_count)
			vty_out(vty, "  Handover: On at %u BTS, Off at %u BTS%s",
				ho_active_count, ho_inactive_count, VTY_NEWLINE);
		else
			vty_out(vty, "  Handover: %s%s", ho_active_count ? "On" : "Off",
				VTY_NEWLINE);
	}

	network_chan_load(&pl, net);
	vty_out(vty, "  Current Channel Load:%s", VTY_NEWLINE);
	dump_pchan_load_vty(vty, "    ", &pl);

	/* show rf */
	if (net->rf_ctrl)
		vty_out(vty, "  Last RF Command: %s%s",
			net->rf_ctrl->last_state_command,
			VTY_NEWLINE);
	if (net->rf_ctrl)
		vty_out(vty, "  Last RF Lock Command: %s%s",
			net->rf_ctrl->last_rf_lock_ctrl_command,
			VTY_NEWLINE);
}

DEFUN(bsc_show_net, bsc_show_net_cmd, "show network",
	SHOW_STR "Display information about a GSM NETWORK\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	net_dump_vty(vty, net);

	return CMD_SUCCESS;
}

static void e1isl_dump_vty(struct vty *vty, struct e1inp_sign_link *e1l)
{
	struct e1inp_line *line;

	if (!e1l) {
		vty_out(vty, "   None%s", VTY_NEWLINE);
		return;
	}

	line = e1l->ts->line;

	vty_out(vty, "    E1 Line %u, Type %s: Timeslot %u, Mode %s%s",
		line->num, line->driver->name, e1l->ts->num,
		e1inp_signtype_name(e1l->type), VTY_NEWLINE);
	vty_out(vty, "    E1 TEI %u, SAPI %u%s",
		e1l->tei, e1l->sapi, VTY_NEWLINE);
}

/*! Dump the IP addresses and ports of the input signal link's timeslot.
 *  This only makes sense for links connected with ipaccess.
 *  Example output: "(r=10.1.42.1:55416<->l=10.1.42.123:3003)" */
static void e1isl_dump_vty_tcp(struct vty *vty, const struct e1inp_sign_link *e1l)
{
	if (e1l) {
		char *name = osmo_sock_get_name(NULL, e1l->ts->driver.ipaccess.fd.fd);
		vty_out(vty, "%s", name);
		talloc_free(name);
	}
	vty_out(vty, "%s", VTY_NEWLINE);
}

static void vty_out_neigh_list(struct vty *vty, struct bitvec *bv)
{
	int count = 0;
	int i;
	for (i = 0; i < 1024; i++) {
		if (!bitvec_get_bit_pos(bv, i))
			continue;
		vty_out(vty, " %u", i);
		count ++;
	}
	if (!count)
		vty_out(vty, " (none)");
	else
		vty_out(vty, " (%d)", count);
}

static void bts_dump_vty_cbch(struct vty *vty, const struct bts_smscb_chan_state *cstate)
{
	vty_out(vty, "  CBCH %s: %u messages, %u pages, %zu-entry sched_arr, %u%% load%s",
		bts_smscb_chan_state_name(cstate), llist_count(&cstate->messages),
		bts_smscb_chan_page_count(cstate), cstate->sched_arr_size,
		bts_smscb_chan_load_percent(cstate), VTY_NEWLINE);
}

static void bts_dump_vty_features(struct vty *vty, struct gsm_bts *bts)
{
	unsigned int i;
	bool no_features = true;
	vty_out(vty, "  Features:%s", VTY_NEWLINE);

	for (i = 0; i < _NUM_BTS_FEAT; i++) {
		if (osmo_bts_has_feature(&bts->features, i)) {
			vty_out(vty, "    %03u ", i);
			vty_out(vty, "%-40s%s", osmo_bts_feature_name(i), VTY_NEWLINE);
			no_features = false;
		}
	}

	if (no_features)
		vty_out(vty, "    (not available)%s", VTY_NEWLINE);
}

static void bts_dump_vty(struct vty *vty, struct gsm_bts *bts)
{
	struct pchan_load pl;
	unsigned long long sec;
	struct gsm_bts_trx *trx;
	int ts_hopping_total;
	int ts_non_hopping_total;

	vty_out(vty, "BTS %u is of %s type in band %s, has CI %u LAC %u, "
		"BSIC %u (NCC=%u, BCC=%u) and %u TRX%s",
		bts->nr, btstype2str(bts->type), gsm_band_name(bts->band),
		bts->cell_identity,
		bts->location_area_code, bts->bsic,
		bts->bsic >> 3, bts->bsic & 7,
		bts->num_trx, VTY_NEWLINE);
	vty_out(vty, "  Description: %s%s",
		bts->description ? bts->description : "(null)", VTY_NEWLINE);

	vty_out(vty, "  ARFCNs:");
	ts_hopping_total = 0;
	ts_non_hopping_total = 0;
	llist_for_each_entry(trx, &bts->trx_list, list) {
		int ts_nr;
		int ts_hopping = 0;
		int ts_non_hopping = 0;
		for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[ts_nr];
			if (ts->hopping.enabled)
				ts_hopping++;
			else
				ts_non_hopping++;
		}

		if (ts_non_hopping)
			vty_out(vty, " %u", trx->arfcn);
		ts_hopping_total += ts_hopping;
		ts_non_hopping_total += ts_non_hopping;
	}
	if (ts_hopping_total) {
		if (ts_non_hopping_total)
			vty_out(vty, " / Hopping on %d of %d timeslots",
				ts_hopping_total, ts_hopping_total + ts_non_hopping_total);
		else
			vty_out(vty, " Hopping on all %d timeslots", ts_hopping_total);
	}
	vty_out(vty, "%s", VTY_NEWLINE);

	if (strnlen(bts->pcu_version, MAX_VERSION_LENGTH))
		vty_out(vty, "  PCU version %s connected%s", bts->pcu_version,
			VTY_NEWLINE);
	vty_out(vty, "  MS Max power: %u dBm%s", bts->ms_max_power, VTY_NEWLINE);
	vty_out(vty, "  Minimum Rx Level for Access: %i dBm%s",
		rxlev2dbm(bts->si_common.cell_sel_par.rxlev_acc_min),
		VTY_NEWLINE);
	vty_out(vty, "  Cell Reselection Hysteresis: %u dBm%s",
		bts->si_common.cell_sel_par.cell_resel_hyst*2, VTY_NEWLINE);
	vty_out(vty, "  Access Control Class rotation allow mask: 0x%" PRIx16 "%s",
		bts->acc_mgr.allowed_subset_mask, VTY_NEWLINE);
	vty_out(vty, "  Access Control Class ramping: %senabled%s",
		acc_ramp_is_enabled(&bts->acc_ramp) ? "" : "not ", VTY_NEWLINE);
	if (acc_ramp_is_enabled(&bts->acc_ramp)) {
		vty_out(vty, "  Access Control Class ramping step interval: %u seconds%s",
			acc_ramp_get_step_interval(&bts->acc_ramp), VTY_NEWLINE);
		vty_out(vty, "  Access Control Class channel load thresholds: (%" PRIu8 ", %" PRIu8 ")%s",
			bts->acc_ramp.chan_load_lower_threshold,
			bts->acc_ramp.chan_load_upper_threshold, VTY_NEWLINE);
	        vty_out(vty, "  enabling %u Access Control Class%s per ramping step%s",
			acc_ramp_get_step_size(&bts->acc_ramp),
			acc_ramp_get_step_size(&bts->acc_ramp) > 1 ? "es" : "", VTY_NEWLINE);
	}
	vty_out(vty, "  RACH TX-Integer: %u%s", bts->si_common.rach_control.tx_integer,
		VTY_NEWLINE);
	vty_out(vty, "  RACH Max transmissions: %u%s",
		rach_max_trans_raw2val(bts->si_common.rach_control.max_trans),
		VTY_NEWLINE);
	if (bts->si_common.rach_control.cell_bar)
		vty_out(vty, "  CELL IS BARRED%s", VTY_NEWLINE);
	if (bts->dtxu != GSM48_DTX_SHALL_NOT_BE_USED)
		vty_out(vty, "  Uplink DTX: %s%s",
			(bts->dtxu != GSM48_DTX_SHALL_BE_USED) ?
			"enabled" : "forced", VTY_NEWLINE);
	else
		vty_out(vty, "  Uplink DTX: not enabled%s", VTY_NEWLINE);
	vty_out(vty, "  Downlink DTX: %senabled%s", bts->dtxd ? "" : "not ",
		VTY_NEWLINE);
	vty_out(vty, "  Channel Description Attachment: %s%s",
		(bts->si_common.chan_desc.att) ? "yes" : "no", VTY_NEWLINE);
	vty_out(vty, "  Channel Description BS-PA-MFRMS: %u%s",
		bts->si_common.chan_desc.bs_pa_mfrms + 2, VTY_NEWLINE);
	vty_out(vty, "  Channel Description BS-AG_BLKS-RES: %u%s",
		bts->si_common.chan_desc.bs_ag_blks_res, VTY_NEWLINE);
	vty_out(vty, "  System Information present: 0x%08x, static: 0x%08x%s",
		bts->si_valid, bts->si_mode_static, VTY_NEWLINE);
	vty_out(vty, "  Early Classmark Sending: 2G %s, 3G %s%s%s",
		bts->early_classmark_allowed ? "allowed" : "forbidden",
		bts->early_classmark_allowed_3g ? "allowed" : "forbidden",
		bts->early_classmark_allowed_3g && !bts->early_classmark_allowed ?
		" (forbidden by 2G bit)" : "",
		VTY_NEWLINE);
	if (bts->pcu_sock_path)
		vty_out(vty, "  PCU Socket Path: %s%s", bts->pcu_sock_path, VTY_NEWLINE);
	if (is_ipaccess_bts(bts))
		vty_out(vty, "  Unit ID: %u/%u/0, OML Stream ID 0x%02x%s",
			bts->ip_access.site_id, bts->ip_access.bts_id,
			bts->oml_tei, VTY_NEWLINE);
	else if (bts->type == GSM_BTS_TYPE_NOKIA_SITE)
		vty_out(vty, "  Skip Reset: %d%s",
			bts->nokia.skip_reset, VTY_NEWLINE);
	vty_out(vty, "  NM State: ");
	net_dump_nmstate(vty, &bts->mo.nm_state);
	vty_out(vty, "  Site Mgr NM State: ");
	net_dump_nmstate(vty, &bts->site_mgr->mo.nm_state);

	if (bts->gprs.mode != BTS_GPRS_NONE) {
		vty_out(vty, "  GPRS NSE: ");
		net_dump_nmstate(vty, &bts->site_mgr->gprs.nse.mo.nm_state);
		vty_out(vty, "  GPRS CELL: ");
		net_dump_nmstate(vty, &bts->gprs.cell.mo.nm_state);
		vty_out(vty, "  GPRS NSVC0: ");
		net_dump_nmstate(vty, &bts->site_mgr->gprs.nsvc[0].mo.nm_state);
		vty_out(vty, "  GPRS NSVC1: ");
		net_dump_nmstate(vty, &bts->site_mgr->gprs.nsvc[1].mo.nm_state);
	} else
		vty_out(vty, "  GPRS: not configured%s", VTY_NEWLINE);

	vty_out(vty, "  Paging: %u pending requests, %u free slots%s",
		paging_pending_requests_nr(bts),
		bts->paging.available_slots, VTY_NEWLINE);
	if (is_ipaccess_bts(bts)) {
		vty_out(vty, "  OML Link: ");
		e1isl_dump_vty_tcp(vty, bts->oml_link);
		vty_out(vty, "  OML Link state: %s", get_model_oml_status(bts));
		sec = bts_uptime(bts);
		if (sec)
			vty_out(vty, " %llu days %llu hours %llu min. %llu sec.",
				OSMO_SEC2DAY(sec), OSMO_SEC2HRS(sec), OSMO_SEC2MIN(sec), sec % 60);
		vty_out(vty, "%s", VTY_NEWLINE);
	} else {
		vty_out(vty, "  E1 Signalling Link:%s", VTY_NEWLINE);
		e1isl_dump_vty(vty, bts->oml_link);
	}

	vty_out(vty, "  Neighbor Cells: ");
	switch (bts->neigh_list_manual_mode) {
	default:
	case NL_MODE_AUTOMATIC:
		vty_out(vty, "Automatic");
		/* generate_bcch_chan_list() should populate si_common.neigh_list */
		break;
	case NL_MODE_MANUAL:
		vty_out(vty, "Manual");
		break;
	case NL_MODE_MANUAL_SI5SEP:
		vty_out(vty, "Manual/separate SI5");
		break;
	}
	vty_out(vty, ", ARFCNs:");
	vty_out_neigh_list(vty, &bts->si_common.neigh_list);
	if (bts->neigh_list_manual_mode == NL_MODE_MANUAL_SI5SEP) {
		vty_out(vty, " SI5:");
		vty_out_neigh_list(vty, &bts->si_common.si5_neigh_list);
	}
	vty_out(vty, "%s", VTY_NEWLINE);

	/* FIXME: chan_desc */
	memset(&pl, 0, sizeof(pl));
	bts_chan_load(&pl, bts);
	vty_out(vty, "  Current Channel Load:%s", VTY_NEWLINE);
	dump_pchan_load_vty(vty, "    ", &pl);

	bts_dump_vty_cbch(vty, &bts->cbch_basic);
	bts_dump_vty_cbch(vty, &bts->cbch_extended);

	vty_out(vty, "  Channel Requests        : %"PRIu64" total, %"PRIu64" no channel%s",
		bts->bts_ctrs->ctr[BTS_CTR_CHREQ_TOTAL].current,
		bts->bts_ctrs->ctr[BTS_CTR_CHREQ_NO_CHANNEL].current,
		VTY_NEWLINE);
	vty_out(vty, "  Channel Failures        : %"PRIu64" rf_failures, %"PRIu64" rll failures%s",
		bts->bts_ctrs->ctr[BTS_CTR_CHAN_RF_FAIL].current,
		bts->bts_ctrs->ctr[BTS_CTR_CHAN_RLL_ERR].current,
		VTY_NEWLINE);
	vty_out(vty, "  BTS failures            : %"PRIu64" OML, %"PRIu64" RSL%s",
		bts->bts_ctrs->ctr[BTS_CTR_BTS_OML_FAIL].current,
		bts->bts_ctrs->ctr[BTS_CTR_BTS_RSL_FAIL].current,
		VTY_NEWLINE);

	vty_out_stat_item_group(vty, "  ", bts->bts_statg);

	bts_dump_vty_features(vty, bts);
}

DEFUN(show_bts, show_bts_cmd, "show bts [<0-255>]",
	SHOW_STR "Display information about a BTS\n"
		"BTS number\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	int bts_nr;

	if (argc != 0) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts_dump_vty(vty, gsm_bts_num(net, bts_nr));
		return CMD_SUCCESS;
	}
	/* print all BTS's */
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++)
		bts_dump_vty(vty, gsm_bts_num(net, bts_nr));

	return CMD_SUCCESS;
}

DEFUN(show_bts_fail_rep, show_bts_fail_rep_cmd, "show bts <0-255> fail-rep [reset]",
	SHOW_STR "Display information about a BTS\n"
		"BTS number\n" "OML failure reports\n"
		"Clear the list of failure reports after showing them\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct bts_oml_fail_rep *entry;
	struct gsm_bts *bts;
	int bts_nr;

	bts_nr = atoi(argv[0]);
	if (bts_nr >= net->num_bts) {
		vty_out(vty, "%% can't find BTS '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(net, bts_nr);
	if (llist_empty(&bts->oml_fail_rep)) {
		vty_out(vty, "No failure reports received.%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	llist_for_each_entry(entry, &bts->oml_fail_rep, list) {
		struct nm_fail_rep_signal_data *sd;
		char timestamp[20]; /* format like 2020-03-23 14:24:00 */
		enum abis_nm_pcause_type pcause;
		enum abis_mm_event_causes cause;

		strftime(timestamp, sizeof(timestamp), "%F %T", localtime(&entry->time));
		sd = abis_nm_fail_evt_rep_parse(entry->mb, bts);
		if (!sd) {
			vty_out(vty, "[%s] (failed to parse report)%s", timestamp, VTY_NEWLINE);
			continue;
		}
		pcause = sd->parsed.probable_cause[0];
		cause = osmo_load16be(sd->parsed.probable_cause + 1);

		vty_out(vty, "[%s] Type=%s, Severity=%s, ", timestamp, sd->parsed.event_type, sd->parsed.severity);
		vty_out(vty, "Probable cause=%s: ", get_value_string(abis_nm_pcause_type_names, pcause));
		if (pcause == NM_PCAUSE_T_MANUF)
			vty_out(vty, "%s, ", get_value_string(abis_mm_event_cause_names, cause));
		else
			vty_out(vty, "%04X, ", cause);
		vty_out(vty, "Additional text=%s%s", sd->parsed.additional_text, VTY_NEWLINE);

		talloc_free(sd);
	}

	/* Optionally clear the list */
	if (argc > 1) {
		while (!llist_empty(&bts->oml_fail_rep)) {
			struct bts_oml_fail_rep *old = llist_last_entry(&bts->oml_fail_rep, struct bts_oml_fail_rep,
									list);
			llist_del(&old->list);
			talloc_free(old);
		}
	}

	return CMD_SUCCESS;
}

DEFUN(show_rejected_bts, show_rejected_bts_cmd, "show rejected-bts",
	SHOW_STR "Display recently rejected BTS devices\n")
{
	struct gsm_bts_rejected *pos;

	/* empty list */
	struct llist_head *rejected = &gsmnet_from_vty(vty)->bts_rejected;
	if (llist_empty(rejected)) {
		vty_out(vty, "No BTS has been rejected.%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	/* table head */
	vty_out(vty, "Date                Site ID BTS ID IP%s", VTY_NEWLINE);
	vty_out(vty, "------------------- ------- ------ ---------------%s", VTY_NEWLINE);

	/* table body */
	llist_for_each_entry(pos, rejected, list) {
		/* timestamp formatted like: "2018-10-24 15:04:52" */
		char buf[20];
		strftime(buf, sizeof(buf), "%F %T", localtime(&pos->time));

		vty_out(vty, "%s %7u %6u %15s%s", buf, pos->site_id, pos->bts_id, pos->ip, VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

/* utility functions */
static void parse_e1_link(struct gsm_e1_subslot *e1_link, const char *line,
			  const char *ts, const char *ss)
{
	e1_link->e1_nr = atoi(line);
	e1_link->e1_ts = atoi(ts);
	if (!strcmp(ss, "full"))
		e1_link->e1_ts_ss = 255;
	else
		e1_link->e1_ts_ss = atoi(ss);
}

static void config_write_e1_link(struct vty *vty, struct gsm_e1_subslot *e1_link,
				 const char *prefix)
{
	if (!e1_link->e1_ts)
		return;

	if (e1_link->e1_ts_ss == 255)
		vty_out(vty, "%se1 line %u timeslot %u sub-slot full%s",
			prefix, e1_link->e1_nr, e1_link->e1_ts, VTY_NEWLINE);
	else
		vty_out(vty, "%se1 line %u timeslot %u sub-slot %u%s",
			prefix, e1_link->e1_nr, e1_link->e1_ts,
			e1_link->e1_ts_ss, VTY_NEWLINE);
}


static void config_write_ts_single(struct vty *vty, struct gsm_bts_trx_ts *ts)
{
	vty_out(vty, "   timeslot %u%s", ts->nr, VTY_NEWLINE);
	if (ts->tsc != -1)
		vty_out(vty, "    training_sequence_code %u%s", ts->tsc, VTY_NEWLINE);
	if (ts->pchan_from_config != GSM_PCHAN_NONE)
		vty_out(vty, "    phys_chan_config %s%s",
			gsm_pchan_name(ts->pchan_from_config), VTY_NEWLINE);
	vty_out(vty, "    hopping enabled %u%s",
		ts->hopping.enabled, VTY_NEWLINE);
	if (ts->hopping.enabled) {
		unsigned int i;
		vty_out(vty, "    hopping sequence-number %u%s",
			ts->hopping.hsn, VTY_NEWLINE);
		vty_out(vty, "    hopping maio %u%s",
			ts->hopping.maio, VTY_NEWLINE);
		for (i = 0; i < ts->hopping.arfcns.data_len*8; i++) {
			if (!bitvec_get_bit_pos(&ts->hopping.arfcns, i))
				continue;
			vty_out(vty, "    hopping arfcn add %u%s",
				i, VTY_NEWLINE);
		}
	}
	config_write_e1_link(vty, &ts->e1_link, "    ");

	if (ts->trx->bts->model->config_write_ts)
		ts->trx->bts->model->config_write_ts(vty, ts);
}

static void config_write_trx_single(struct vty *vty, struct gsm_bts_trx *trx)
{
	int i;

	vty_out(vty, "  trx %u%s", trx->nr, VTY_NEWLINE);
	if (trx->description)
		vty_out(vty, "   description %s%s", trx->description,
			VTY_NEWLINE);
	vty_out(vty, "   rf_locked %u%s",
		trx->mo.force_rf_lock ? 1 : 0,
		VTY_NEWLINE);
	vty_out(vty, "   arfcn %u%s", trx->arfcn, VTY_NEWLINE);
	vty_out(vty, "   nominal power %u%s", trx->nominal_power, VTY_NEWLINE);
	vty_out(vty, "   max_power_red %u%s", trx->max_power_red, VTY_NEWLINE);
	config_write_e1_link(vty, &trx->rsl_e1_link, "   rsl ");
	vty_out(vty, "   rsl e1 tei %u%s", trx->rsl_tei, VTY_NEWLINE);

	if (trx->bts->model->config_write_trx)
		trx->bts->model->config_write_trx(vty, trx);

	for (i = 0; i < TRX_NR_TS; i++)
		config_write_ts_single(vty, &trx->ts[i]);
}

static void config_write_bts_gprs(struct vty *vty, struct gsm_bts *bts)
{
	unsigned int i;
	struct gsm_bts_sm *bts_sm = bts->site_mgr;
	vty_out(vty, "  gprs mode %s%s", bts_gprs_mode_name(bts->gprs.mode),
		VTY_NEWLINE);
	if (bts->gprs.mode == BTS_GPRS_NONE)
		return;

	vty_out(vty, "  gprs routing area %u%s", bts->gprs.rac,
		VTY_NEWLINE);
	vty_out(vty, "  gprs network-control-order nc%u%s",
		bts->gprs.net_ctrl_ord, VTY_NEWLINE);
	if (!bts->gprs.ctrl_ack_type_use_block)
		vty_out(vty, "  gprs control-ack-type-rach%s", VTY_NEWLINE);
	if (bts->gprs.ccn.forced_vty)
		vty_out(vty, "  gprs ccn-active %d%s",
			bts->gprs.ccn.active ? 1 : 0, VTY_NEWLINE);
	vty_out(vty, "  gprs power-control alpha %u%s",
		bts->gprs.pwr_ctrl.alpha, VTY_NEWLINE);
	vty_out(vty, "  gprs cell bvci %u%s", bts->gprs.cell.bvci,
		VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(bts->gprs.cell.timer); i++)
		vty_out(vty, "  gprs cell timer %s %u%s",
			get_value_string(gprs_bssgp_cfg_strs, i),
			bts->gprs.cell.timer[i], VTY_NEWLINE);
	vty_out(vty, "  gprs nsei %u%s", bts_sm->gprs.nse.nsei,
		VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(bts_sm->gprs.nse.timer); i++)
		vty_out(vty, "  gprs ns timer %s %u%s",
			get_value_string(gprs_ns_timer_strs, i),
			bts_sm->gprs.nse.timer[i], VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(bts_sm->gprs.nsvc); i++) {
		const struct gsm_gprs_nsvc *nsvc = &bts_sm->gprs.nsvc[i];
		struct osmo_sockaddr_str remote;

		vty_out(vty, "  gprs nsvc %u nsvci %u%s", i,
			nsvc->nsvci, VTY_NEWLINE);

		vty_out(vty, "  gprs nsvc %u local udp port %u%s", i,
			nsvc->local_port, VTY_NEWLINE);

		/* Most likely, the remote address is not configured (AF_UNSPEC).
		 * Printing the port alone makes no sense, so let's just skip both. */
		if (osmo_sockaddr_str_from_sockaddr(&remote, &nsvc->remote.u.sas) != 0)
			continue;

		vty_out(vty, "  gprs nsvc %u remote ip %s%s",
			i, remote.ip, VTY_NEWLINE);
		vty_out(vty, "  gprs nsvc %u remote udp port %u%s",
			i, remote.port, VTY_NEWLINE);
	}

	/* EGPRS specific parameters */
	if (bts->gprs.mode == BTS_GPRS_EGPRS) {
		if (bts->gprs.egprs_pkt_chan_request)
			vty_out(vty, "  gprs egprs-packet-channel-request%s", VTY_NEWLINE);
	}
}

/* Write the model data if there is one */
static void config_write_bts_model(struct vty *vty, struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	if (!bts->model)
		return;

	if (bts->model->config_write_bts)
		bts->model->config_write_bts(vty, bts);

	llist_for_each_entry(trx, &bts->trx_list, list)
		config_write_trx_single(vty, trx);
}

static void write_amr_modes(struct vty *vty, const char *prefix,
	const char *name, struct amr_mode *modes, int num)
{
	int i;

	vty_out(vty, "  %s threshold %s", prefix, name);
	for (i = 0; i < num - 1; i++)
		vty_out(vty, " %d", modes[i].threshold);
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "  %s hysteresis %s", prefix, name);
	for (i = 0; i < num - 1; i++)
		vty_out(vty, " %d", modes[i].hysteresis);
	vty_out(vty, "%s", VTY_NEWLINE);
}

static void config_write_bts_amr(struct vty *vty, struct gsm_bts *bts,
	struct amr_multirate_conf *mr, int full)
{
	struct gsm48_multi_rate_conf *mr_conf;
	const char *prefix = (full) ? "amr tch-f" : "amr tch-h";
	int i, num;

	if (!(mr->gsm48_ie[1]))
		return;

	mr_conf = (struct gsm48_multi_rate_conf *) mr->gsm48_ie;

	num = 0;
	vty_out(vty, "  %s modes", prefix);
	for (i = 0; i < ((full) ? 8 : 6); i++) {
		if ((mr->gsm48_ie[1] & (1 << i))) {
			vty_out(vty, " %d", i);
			num++;
		}
	}
	vty_out(vty, "%s", VTY_NEWLINE);
	if (num > 4)
		num = 4;
	if (num > 1) {
		write_amr_modes(vty, prefix, "ms", mr->ms_mode, num);
		write_amr_modes(vty, prefix, "bts", mr->bts_mode, num);
	}
	vty_out(vty, "  %s start-mode ", prefix);
	if (mr_conf->icmi) {
		num = 0;
		for (i = 0; i < ((full) ? 8 : 6) && num < 4; i++) {
			if ((mr->gsm48_ie[1] & (1 << i)))
				num++;
			if (mr_conf->smod == num - 1) {
				vty_out(vty, "%d%s", num, VTY_NEWLINE);
				break;
			}
		}
	} else
		vty_out(vty, "auto%s", VTY_NEWLINE);
}

/* TODO: generalize and move indention handling to libosmocore */
#define cfg_out(fmt, args...) \
	vty_out(vty, "%*s" fmt, indent, "", ##args);

static void config_write_power_ctrl_meas(struct vty *vty, unsigned int indent,
					 const struct gsm_power_ctrl_params *cp,
					 uint8_t ptype)
{
	const struct gsm_power_ctrl_meas_params *mp;
	const char *param;

	switch (ptype) {
	case IPAC_RXLEV_AVE:
		mp = &cp->rxlev_meas;
		param = "rxlev";
		break;
	case IPAC_RXQUAL_AVE:
		mp = &cp->rxqual_meas;
		param = "rxqual";
		break;
	default:
		/* Shall not happen */
		OSMO_ASSERT(0);
	}

	cfg_out("%s-thresh lower %u upper %u%s",
		param, mp->lower_thresh, mp->upper_thresh,
		VTY_NEWLINE);
	cfg_out("%s-thresh-comp lower %u %u upper %u %u%s",
		param, mp->lower_cmp_p, mp->lower_cmp_n,
		mp->upper_cmp_p, mp->upper_cmp_n,
		VTY_NEWLINE);

	switch (mp->algo) {
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE:
		/* Do not print any averaging parameters */
		return; /* we're done */
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_UNWEIGHTED:
		cfg_out("%s-avg algo unweighted%s", param, VTY_NEWLINE);
		break;
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_WEIGHTED:
		cfg_out("%s-avg algo weighted%s", param, VTY_NEWLINE);
		break;
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_MOD_MEDIAN:
		cfg_out("%s-avg algo mod-median%s", param, VTY_NEWLINE);
		break;
	case GSM_PWR_CTRL_MEAS_AVG_ALGO_OSMO_EWMA:
		cfg_out("%s-avg algo osmo-ewma beta %u%s",
			param, 100 - mp->ewma.alpha,
			VTY_NEWLINE);
		break;
	}

	cfg_out("%s-avg params hreqave %u hreqt %u%s",
		param, mp->h_reqave, mp->h_reqt,
		VTY_NEWLINE);
}

static void config_write_power_ctrl(struct vty *vty, unsigned int indent,
				    const struct gsm_power_ctrl_params *cp)
{
	const char *node_name;

	if (cp->dir == GSM_PWR_CTRL_DIR_UL)
		node_name = "ms-power-control";
	else
		node_name = "bs-power-control";

	switch (cp->mode) {
	case GSM_PWR_CTRL_MODE_NONE:
		cfg_out("no %s%s", node_name, VTY_NEWLINE);
		break;
	case GSM_PWR_CTRL_MODE_STATIC:
		cfg_out("%s%s", node_name, VTY_NEWLINE);
		cfg_out(" mode static%s", VTY_NEWLINE);
		if (cp->dir == GSM_PWR_CTRL_DIR_DL && cp->bs_power_val_db != 0)
			cfg_out(" bs-power static %u%s", cp->bs_power_val_db, VTY_NEWLINE);
		break;
	case GSM_PWR_CTRL_MODE_DYN_BTS:
		cfg_out("%s%s", node_name, VTY_NEWLINE);
		cfg_out(" mode dyn-bts%s", VTY_NEWLINE);
		if (cp->dir == GSM_PWR_CTRL_DIR_DL)
			cfg_out(" bs-power dyn-max %u%s", cp->bs_power_max_db, VTY_NEWLINE);

		if (cp->ctrl_interval > 0)
			cfg_out(" ctrl-interval %u%s", cp->ctrl_interval, VTY_NEWLINE);
		cfg_out(" step-size inc %u red %u%s",
			cp->inc_step_size_db, cp->red_step_size_db,
			VTY_NEWLINE);

		/* Measurement processing / averaging parameters */
		config_write_power_ctrl_meas(vty, indent + 1, cp, IPAC_RXLEV_AVE);
		config_write_power_ctrl_meas(vty, indent + 1, cp, IPAC_RXQUAL_AVE);
		break;
	}
}

#undef cfg_out

static void config_write_bts_single(struct vty *vty, struct gsm_bts *bts)
{
	int i;
	uint8_t tmp;

	vty_out(vty, " bts %u%s", bts->nr, VTY_NEWLINE);
	vty_out(vty, "  type %s%s", btstype2str(bts->type), VTY_NEWLINE);
	if (bts->description)
		vty_out(vty, "  description %s%s", bts->description, VTY_NEWLINE);
	vty_out(vty, "  band %s%s", gsm_band_name(bts->band), VTY_NEWLINE);
	vty_out(vty, "  cell_identity %u%s", bts->cell_identity, VTY_NEWLINE);
	vty_out(vty, "  location_area_code %u%s", bts->location_area_code,
		VTY_NEWLINE);
	if (bts->dtxu != GSM48_DTX_SHALL_NOT_BE_USED)
		vty_out(vty, "  dtx uplink%s%s",
			(bts->dtxu != GSM48_DTX_SHALL_BE_USED) ? "" : " force",
			VTY_NEWLINE);
	if (bts->dtxd)
		vty_out(vty, "  dtx downlink%s", VTY_NEWLINE);
	vty_out(vty, "  base_station_id_code %u%s", bts->bsic, VTY_NEWLINE);
	vty_out(vty, "  ms max power %u%s", bts->ms_max_power, VTY_NEWLINE);
	vty_out(vty, "  cell reselection hysteresis %u%s",
		bts->si_common.cell_sel_par.cell_resel_hyst*2, VTY_NEWLINE);
	vty_out(vty, "  rxlev access min %u%s",
		bts->si_common.cell_sel_par.rxlev_acc_min, VTY_NEWLINE);

	if (bts->si_common.cell_ro_sel_par.present) {
		struct osmo_gsm48_si_selection_params *sp;
		sp = &bts->si_common.cell_ro_sel_par;

		if (sp->cbq)
			vty_out(vty, "  cell bar qualify %u%s",
				sp->cbq, VTY_NEWLINE);

		if (sp->cell_resel_off)
			vty_out(vty, "  cell reselection offset %u%s",
				sp->cell_resel_off*2, VTY_NEWLINE);

		if (sp->temp_offs == 7)
			vty_out(vty, "  temporary offset infinite%s",
				VTY_NEWLINE);
		else if (sp->temp_offs)
			vty_out(vty, "  temporary offset %u%s",
				sp->temp_offs*10, VTY_NEWLINE);

		if (sp->penalty_time == 31)
			vty_out(vty, "  penalty time reserved%s",
				VTY_NEWLINE);
		else if (sp->penalty_time)
			vty_out(vty, "  penalty time %u%s",
				(sp->penalty_time*20)+20, VTY_NEWLINE);
	}

	if (gsm_bts_get_radio_link_timeout(bts) < 0)
		vty_out(vty, "  radio-link-timeout infinite%s", VTY_NEWLINE);
	else
		vty_out(vty, "  radio-link-timeout %d%s",
			gsm_bts_get_radio_link_timeout(bts), VTY_NEWLINE);

	vty_out(vty, "  channel allocator %s%s",
		bts->chan_alloc_reverse ? "descending" : "ascending",
		VTY_NEWLINE);
	vty_out(vty, "  rach tx integer %u%s",
		bts->si_common.rach_control.tx_integer, VTY_NEWLINE);
	vty_out(vty, "  rach max transmission %u%s",
		rach_max_trans_raw2val(bts->si_common.rach_control.max_trans),
		VTY_NEWLINE);

	vty_out(vty, "  channel-description attach %u%s",
		bts->si_common.chan_desc.att, VTY_NEWLINE);
	vty_out(vty, "  channel-description bs-pa-mfrms %u%s",
		bts->si_common.chan_desc.bs_pa_mfrms + 2, VTY_NEWLINE);
	vty_out(vty, "  channel-description bs-ag-blks-res %u%s",
		bts->si_common.chan_desc.bs_ag_blks_res, VTY_NEWLINE);

	if (bts->ccch_load_ind_thresh != 10)
		vty_out(vty, "  ccch load-indication-threshold %u%s",
			bts->ccch_load_ind_thresh, VTY_NEWLINE);
	if (bts->rach_b_thresh != -1)
		vty_out(vty, "  rach nm busy threshold %u%s",
			bts->rach_b_thresh, VTY_NEWLINE);
	if (bts->rach_ldavg_slots != -1)
		vty_out(vty, "  rach nm load average %u%s",
			bts->rach_ldavg_slots, VTY_NEWLINE);
	if (bts->si_common.rach_control.cell_bar)
		vty_out(vty, "  cell barred 1%s", VTY_NEWLINE);
	if ((bts->si_common.rach_control.t2 & 0x4) == 0)
		vty_out(vty, "  rach emergency call allowed 1%s", VTY_NEWLINE);
	if ((bts->si_common.rach_control.t3) != 0)
		for (i = 0; i < 8; i++)
			if (bts->si_common.rach_control.t3 & (0x1 << i))
				vty_out(vty, "  rach access-control-class %d barred%s", i, VTY_NEWLINE);
	if ((bts->si_common.rach_control.t2 & 0xfb) != 0)
		for (i = 0; i < 8; i++)
			if ((i != 2) && (bts->si_common.rach_control.t2 & (0x1 << i)))
				vty_out(vty, "  rach access-control-class %d barred%s", i+8, VTY_NEWLINE);
	if (bts->acc_mgr.len_allowed_adm < 10)
		vty_out(vty, "  access-control-class-rotate %" PRIu8 "%s", bts->acc_mgr.len_allowed_adm, VTY_NEWLINE);
	if (bts->acc_mgr.rotation_time_sec != ACC_MGR_QUANTUM_DEFAULT)
		vty_out(vty, "  access-control-class-rotate-quantum %" PRIu32 "%s", bts->acc_mgr.rotation_time_sec, VTY_NEWLINE);
	vty_out(vty, "  %saccess-control-class-ramping%s", acc_ramp_is_enabled(&bts->acc_ramp) ? "" : "no ", VTY_NEWLINE);
	if (acc_ramp_is_enabled(&bts->acc_ramp)) {
		vty_out(vty, "  access-control-class-ramping-step-interval %u%s",
			acc_ramp_get_step_interval(&bts->acc_ramp), VTY_NEWLINE);
		vty_out(vty, "  access-control-class-ramping-step-size %u%s", acc_ramp_get_step_size(&bts->acc_ramp),
			VTY_NEWLINE);
		vty_out(vty, "  access-control-class-ramping-chan-load %u %u%s",
			bts->acc_ramp.chan_load_lower_threshold, bts->acc_ramp.chan_load_upper_threshold, VTY_NEWLINE);
	}
	if (!bts->si_unused_send_empty)
		vty_out(vty, "  no system-information unused-send-empty%s", VTY_NEWLINE);
	for (i = SYSINFO_TYPE_1; i < _MAX_SYSINFO_TYPE; i++) {
		if (bts->si_mode_static & (1 << i)) {
			vty_out(vty, "  system-information %s mode static%s",
				get_value_string(osmo_sitype_strs, i), VTY_NEWLINE);
			vty_out(vty, "  system-information %s static %s%s",
				get_value_string(osmo_sitype_strs, i),
				osmo_hexdump_nospc(GSM_BTS_SI(bts, i), GSM_MACBLOCK_LEN),
				VTY_NEWLINE);
		}
	}
	vty_out(vty, "  early-classmark-sending %s%s",
		bts->early_classmark_allowed ? "allowed" : "forbidden", VTY_NEWLINE);
	vty_out(vty, "  early-classmark-sending-3g %s%s",
		bts->early_classmark_allowed_3g ? "allowed" : "forbidden", VTY_NEWLINE);
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMOBTS:
		vty_out(vty, "  ipa unit-id %u %u%s",
			bts->ip_access.site_id, bts->ip_access.bts_id, VTY_NEWLINE);
		if (bts->ip_access.rsl_ip) {
			struct in_addr ia;
			ia.s_addr = htonl(bts->ip_access.rsl_ip);
			vty_out(vty, "  ipa rsl-ip %s%s", inet_ntoa(ia),
				VTY_NEWLINE);
		}
		vty_out(vty, "  oml ipa stream-id %u line %u%s",
			bts->oml_tei, bts->oml_e1_link.e1_nr, VTY_NEWLINE);
		break;
	case GSM_BTS_TYPE_NOKIA_SITE:
		vty_out(vty, "  nokia_site skip-reset %d%s", bts->nokia.skip_reset, VTY_NEWLINE);
		vty_out(vty, "  nokia_site no-local-rel-conf %d%s",
			bts->nokia.no_loc_rel_cnf, VTY_NEWLINE);
		vty_out(vty, "  nokia_site bts-reset-timer %d%s", bts->nokia.bts_reset_timer_cnf, VTY_NEWLINE);
		/* fall through: Nokia requires "oml e1" parameters also */
	default:
		config_write_e1_link(vty, &bts->oml_e1_link, "  oml ");
		vty_out(vty, "  oml e1 tei %u%s", bts->oml_tei, VTY_NEWLINE);
		break;
	}

	/* if we have a limit, write it */
	if (bts->paging.free_chans_need >= 0)
		vty_out(vty, "  paging free %d%s", bts->paging.free_chans_need, VTY_NEWLINE);

	vty_out(vty, "  neighbor-list mode %s%s",
		get_value_string(bts_neigh_mode_strs, bts->neigh_list_manual_mode), VTY_NEWLINE);
	if (bts->neigh_list_manual_mode != NL_MODE_AUTOMATIC) {
		for (i = 0; i < 1024; i++) {
			if (bitvec_get_bit_pos(&bts->si_common.neigh_list, i))
				vty_out(vty, "  neighbor-list add arfcn %u%s",
					i, VTY_NEWLINE);
		}
	}
	if (bts->neigh_list_manual_mode == NL_MODE_MANUAL_SI5SEP) {
		for (i = 0; i < 1024; i++) {
			if (bitvec_get_bit_pos(&bts->si_common.si5_neigh_list, i))
				vty_out(vty, "  si5 neighbor-list add arfcn %u%s",
					i, VTY_NEWLINE);
		}
	}

	for (i = 0; i < MAX_EARFCN_LIST; i++) {
		struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
		if (e->arfcn[i] != OSMO_EARFCN_INVALID) {
			vty_out(vty, "  si2quater neighbor-list add earfcn %u "
				"thresh-hi %u", e->arfcn[i], e->thresh_hi);

			vty_out(vty, " thresh-lo %u",
				e->thresh_lo_valid ? e->thresh_lo : 32);

			vty_out(vty, " prio %u",
				e->prio_valid ? e->prio : 8);

			vty_out(vty, " qrxlv %u",
				e->qrxlm_valid ? e->qrxlm : 32);

			tmp = e->meas_bw[i];
			vty_out(vty, " meas %u",
				(tmp != OSMO_EARFCN_MEAS_INVALID) ? tmp : 8);

			vty_out(vty, "%s", VTY_NEWLINE);
		}
	}

	for (i = 0; i < bts->si_common.uarfcn_length; i++) {
		vty_out(vty, "  si2quater neighbor-list add uarfcn %u %u %u%s",
			bts->si_common.data.uarfcn_list[i],
			bts->si_common.data.scramble_list[i] & ~(1 << 9),
			(bts->si_common.data.scramble_list[i] >> 9) & 1,
			VTY_NEWLINE);
	}

	neighbor_ident_vty_write_bts(vty, "  ", bts);

	vty_out(vty, "  codec-support fr");
	if (bts->codec.hr)
		vty_out(vty, " hr");
	if (bts->codec.efr)
		vty_out(vty, " efr");
	if (bts->codec.amr)
		vty_out(vty, " amr");
	vty_out(vty, "%s", VTY_NEWLINE);

	config_write_bts_amr(vty, bts, &bts->mr_full, 1);
	config_write_bts_amr(vty, bts, &bts->mr_half, 0);

	config_write_bts_gprs(vty, bts);

	if (bts->excl_from_rf_lock)
		vty_out(vty, "  rf-lock-exclude%s", VTY_NEWLINE);

	if (bts->force_combined_si_set)
		vty_out(vty, "  %sforce-combined-si%s",
			bts->force_combined_si ? "" : "no ", VTY_NEWLINE);

	for (i = 0; i < ARRAY_SIZE(bts->depends_on); ++i) {
		int j;

		if (bts->depends_on[i] == 0)
			continue;

		for (j = 0; j < sizeof(bts->depends_on[i]) * 8; ++j) {
			int bts_nr;

			if ((bts->depends_on[i] & (1<<j)) == 0)
				continue;

			bts_nr = (i * sizeof(bts->depends_on[i]) * 8) + j;
			vty_out(vty, "  depends-on-bts %d%s", bts_nr, VTY_NEWLINE);
		}
	}
	if (bts->pcu_sock_path)
		vty_out(vty, "  pcu-socket %s%s", bts->pcu_sock_path, VTY_NEWLINE);

	ho_vty_write_bts(vty, bts);

	if (bts->repeated_acch_policy.dl_facch_all)
		vty_out(vty, "  repeat dl-facch all%s", VTY_NEWLINE);
	else if (bts->repeated_acch_policy.dl_facch_cmd)
		vty_out(vty, "  repeat dl-facch command%s", VTY_NEWLINE);
	if (bts->repeated_acch_policy.dl_sacch)
		vty_out(vty, "  repeat dl-sacch%s", VTY_NEWLINE);
	if (bts->repeated_acch_policy.ul_sacch)
		vty_out(vty, "  repeat ul-sacch%s", VTY_NEWLINE);
	if (bts->repeated_acch_policy.ul_sacch
	    || bts->repeated_acch_policy.dl_facch_cmd
	    || bts->repeated_acch_policy.dl_facch_cmd)
		vty_out(vty, "  repeat rxqual %u%s", bts->repeated_acch_policy.rxqual, VTY_NEWLINE);

	/* BS/MS Power Control parameters */
	config_write_power_ctrl(vty, 2, &bts->bs_power_ctrl);
	config_write_power_ctrl(vty, 2, &bts->ms_power_ctrl);

	config_write_bts_model(vty, bts);
}

static int config_write_bts(struct vty *v)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(v);
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &gsmnet->bts_list, list)
		config_write_bts_single(v, bts);

	return CMD_SUCCESS;
}

static int config_write_net(struct vty *vty)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	int i;
	struct osmo_nri_range *r;

	vty_out(vty, "network%s", VTY_NEWLINE);
	vty_out(vty, " network country code %s%s", osmo_mcc_name(gsmnet->plmn.mcc), VTY_NEWLINE);
	vty_out(vty, " mobile network code %s%s",
		osmo_mnc_name(gsmnet->plmn.mnc, gsmnet->plmn.mnc_3_digits), VTY_NEWLINE);
	vty_out(vty, " encryption a5");
	for (i = 0; i < 8; i++) {
		if (gsmnet->a5_encryption_mask & (1 << i))
			vty_out(vty, " %u", i);
	}
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, " neci %u%s", gsmnet->neci, VTY_NEWLINE);
	vty_out(vty, " paging any use tch %d%s", gsmnet->pag_any_tch, VTY_NEWLINE);

	ho_vty_write_net(vty, gsmnet);

	if (!gsmnet->dyn_ts_allow_tch_f)
		vty_out(vty, " dyn_ts_allow_tch_f 0%s", VTY_NEWLINE);
	if (gsmnet->tz.override != 0) {
		if (gsmnet->tz.dst)
			vty_out(vty, " timezone %d %d %d%s",
				gsmnet->tz.hr, gsmnet->tz.mn, gsmnet->tz.dst,
				VTY_NEWLINE);
		else
			vty_out(vty, " timezone %d %d%s",
				gsmnet->tz.hr, gsmnet->tz.mn, VTY_NEWLINE);
	}

	/* Timer introspection commands (generic osmo_tdef API) */
	osmo_tdef_vty_groups_write(vty, " ");

	{
		uint16_t meas_port;
		char *meas_host;
		const char *meas_scenario;

		meas_feed_cfg_get(&meas_host, &meas_port);
		meas_scenario = meas_feed_scenario_get();

		if (meas_port)
			vty_out(vty, " meas-feed destination %s %u%s",
				meas_host, meas_port, VTY_NEWLINE);
		if (strlen(meas_scenario) > 0)
			vty_out(vty, " meas-feed scenario %s%s",
				meas_scenario, VTY_NEWLINE);
	}

	if (gsmnet->allow_unusable_timeslots)
		vty_out(vty, " allow-unusable-timeslots%s", VTY_NEWLINE);

	if (gsmnet->nri_bitlen != OSMO_NRI_BITLEN_DEFAULT)
		vty_out(vty, " nri bitlen %u%s", gsmnet->nri_bitlen, VTY_NEWLINE);

	llist_for_each_entry(r, &gsmnet->null_nri_ranges->entries, entry) {
		vty_out(vty, " nri null add %d", r->first);
		if (r->first != r->last)
			vty_out(vty, " %d", r->last);
		vty_out(vty, "%s", VTY_NEWLINE);
	}

	neighbor_ident_vty_write_network(vty, " ");

	return CMD_SUCCESS;
}

static void trx_dump_vty(struct vty *vty, struct gsm_bts_trx *trx, bool print_rsl, bool show_connected)
{
	if (show_connected && !trx->rsl_link)
		return;

	if (!show_connected && trx->rsl_link)
		return;

	vty_out(vty, "TRX %u of BTS %u is on ARFCN %u%s",
		trx->nr, trx->bts->nr, trx->arfcn, VTY_NEWLINE);
	vty_out(vty, "Description: %s%s",
		trx->description ? trx->description : "(null)", VTY_NEWLINE);
	vty_out(vty, "  RF Nominal Power: %d dBm, reduced by %u dB, "
		"resulting BS power: %d dBm%s",
		trx->nominal_power, trx->max_power_red,
		trx->nominal_power - trx->max_power_red, VTY_NEWLINE);
	vty_out(vty, "  Radio Carrier NM State: ");
	net_dump_nmstate(vty, &trx->mo.nm_state);
	if (print_rsl)
		vty_out(vty, "  RSL State: %s%s", trx->rsl_link? "connected" : "disconnected", VTY_NEWLINE);
	vty_out(vty, "  Baseband Transceiver NM State: ");
	net_dump_nmstate(vty, &trx->bb_transc.mo.nm_state);
	if (is_ipaccess_bts(trx->bts)) {
		vty_out(vty, "  ip.access stream ID: 0x%02x ", trx->rsl_tei);
		e1isl_dump_vty_tcp(vty, trx->rsl_link);
	} else {
		vty_out(vty, "  E1 Signalling Link:%s", VTY_NEWLINE);
		e1isl_dump_vty(vty, trx->rsl_link);
	}
}

static void trx_dump_vty_all(struct vty *vty, struct gsm_bts_trx *trx)
{
	trx_dump_vty(vty, trx, true, true);
	trx_dump_vty(vty, trx, true, false);
}

static inline void print_all_trx(struct vty *vty, const struct gsm_bts *bts)
{
	uint8_t trx_nr;
	for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++)
		trx_dump_vty_all(vty, gsm_bts_trx_num(bts, trx_nr));
}

DEFUN(show_trx,
      show_trx_cmd,
      "show trx [<0-255>] [<0-255>]",
	SHOW_STR "Display information about a TRX\n"
	BTS_TRX_STR)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts = NULL;
	int bts_nr, trx_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX '%s'%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx_dump_vty_all(vty, gsm_bts_trx_num(bts, trx_nr));

		return CMD_SUCCESS;
	}
	if (bts) {
		/* print all TRX in this BTS */
		print_all_trx(vty, bts);
		return CMD_SUCCESS;
	}

	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++)
		print_all_trx(vty, gsm_bts_num(net, bts_nr));

	return CMD_SUCCESS;
}

/* call vty_out() to print a string like " as TCH/H" for dynamic timeslots.
 * Don't do anything if the ts is not dynamic. */
static void vty_out_dyn_ts_status(struct vty *vty, struct gsm_bts_trx_ts *ts)
{
	enum gsm_phys_chan_config target;
	if (ts_is_pchan_switching(ts, &target)) {
		vty_out(vty, " switching %s -> %s", gsm_pchan_name(ts->pchan_is),
			gsm_pchan_name(target));
	} else if (ts->pchan_is != ts->pchan_on_init) {
		vty_out(vty, " as %s", gsm_pchan_name(ts->pchan_is));
	}
}

static void vty_out_dyn_ts_details(struct vty *vty, struct gsm_bts_trx_ts *ts)
{
	/* show dyn TS details, if applicable */
	switch (ts->pchan_on_init) {
	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
		vty_out(vty, "  Osmocom Dyn TS:");
		vty_out_dyn_ts_status(vty, ts);
		vty_out(vty, VTY_NEWLINE);
		break;
	case GSM_PCHAN_TCH_F_PDCH:
		vty_out(vty, "  IPACC Dyn PDCH TS:");
		vty_out_dyn_ts_status(vty, ts);
		vty_out(vty, VTY_NEWLINE);
		break;
	default:
		/* no dyn ts */
		break;
	}
}

static void ts_dump_vty(struct vty *vty, struct gsm_bts_trx_ts *ts)
{
	vty_out(vty, "BTS %u, TRX %u, Timeslot %u, phys cfg %s (active %s)",
		ts->trx->bts->nr, ts->trx->nr, ts->nr,
		gsm_pchan_name(ts->pchan_on_init),
		gsm_pchan_name(ts->pchan_is));
	if (ts->pchan_is != ts->pchan_on_init)
		vty_out(vty, " (%s mode)", gsm_pchan_name(ts->pchan_is));
	vty_out(vty, ", TSC %u%s  NM State: ", gsm_ts_tsc(ts), VTY_NEWLINE);
	vty_out_dyn_ts_details(vty, ts);
	net_dump_nmstate(vty, &ts->mo.nm_state);
	if (!is_ipaccess_bts(ts->trx->bts))
		vty_out(vty, "  E1 Line %u, Timeslot %u, Subslot %u%s",
			ts->e1_link.e1_nr, ts->e1_link.e1_ts,
			ts->e1_link.e1_ts_ss, VTY_NEWLINE);
}

DEFUN(show_ts,
      show_ts_cmd,
      "show timeslot [<0-255>] [<0-255>] [<0-7>]",
	SHOW_STR "Display information about a TS\n"
	BTS_TRX_TS_STR)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts = NULL;
	struct gsm_bts_trx *trx = NULL;
	struct gsm_bts_trx_ts *ts = NULL;
	int bts_nr, trx_nr, ts_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX '%s'%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx = gsm_bts_trx_num(bts, trx_nr);
	}
	if (argc >= 3) {
		ts_nr = atoi(argv[2]);
		if (ts_nr >= TRX_NR_TS) {
			vty_out(vty, "%% can't find TS '%s'%s", argv[2],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		/* Fully Specified: print and exit */
		ts = &trx->ts[ts_nr];
		ts_dump_vty(vty, ts);
		return CMD_SUCCESS;
	}

	if (bts && trx) {
		/* Iterate over all TS in this TRX */
		for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
			ts = &trx->ts[ts_nr];
			ts_dump_vty(vty, ts);
		}
	} else if (bts) {
		/* Iterate over all TRX in this BTS, TS in each TRX */
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = gsm_bts_trx_num(bts, trx_nr);
			for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
				ts = &trx->ts[ts_nr];
				ts_dump_vty(vty, ts);
			}
		}
	} else {
		/* Iterate over all BTS, TRX in each BTS, TS in each TRX */
		for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
			bts = gsm_bts_num(net, bts_nr);
			for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
				trx = gsm_bts_trx_num(bts, trx_nr);
				for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
					ts = &trx->ts[ts_nr];
					ts_dump_vty(vty, ts);
				}
			}
		}
	}

	return CMD_SUCCESS;
}

static void bsc_subscr_dump_vty(struct vty *vty, struct bsc_subscr *bsub)
{
	if (strlen(bsub->imsi))
		vty_out(vty, "    IMSI: %s%s", bsub->imsi, VTY_NEWLINE);
	if (bsub->tmsi != GSM_RESERVED_TMSI)
		vty_out(vty, "    TMSI: 0x%08x%s", bsub->tmsi,
			VTY_NEWLINE);
	vty_out(vty, "    Use count: %s%s", osmo_use_count_to_str_c(OTC_SELECT, &bsub->use_count), VTY_NEWLINE);
}

static void meas_rep_dump_uni_vty(struct vty *vty,
				  struct gsm_meas_rep_unidir *mru,
				  const char *prefix,
				  const char *dir)
{
	vty_out(vty, "%s  RXL-FULL-%s: %4d dBm, RXL-SUB-%s: %4d dBm ",
		prefix, dir, rxlev2dbm(mru->full.rx_lev),
			dir, rxlev2dbm(mru->sub.rx_lev));
	vty_out(vty, "RXQ-FULL-%s: %d, RXQ-SUB-%s: %d%s",
		dir, mru->full.rx_qual, dir, mru->sub.rx_qual,
		VTY_NEWLINE);
}

static void meas_rep_dump_vty(struct vty *vty, struct gsm_meas_rep *mr,
			      const char *prefix)
{
	vty_out(vty, "%sMeasurement Report:%s", prefix, VTY_NEWLINE);
	vty_out(vty, "%s  Flags: %s%s%s%s%s", prefix,
			mr->flags & MEAS_REP_F_UL_DTX ? "DTXu " : "",
			mr->flags & MEAS_REP_F_DL_DTX ? "DTXd " : "",
			mr->flags & MEAS_REP_F_FPC ? "FPC " : "",
			mr->flags & MEAS_REP_F_DL_VALID ? " " : "DLinval ",
			VTY_NEWLINE);
	if (mr->flags & MEAS_REP_F_MS_TO)
		vty_out(vty, "%s  MS Timing Offset: %d%s", prefix, mr->ms_timing_offset, VTY_NEWLINE);
	if (mr->flags & MEAS_REP_F_MS_L1)
		vty_out(vty, "%s  L1 MS Power: %u dBm, Timing Advance: %u%s",
			prefix, mr->ms_l1.pwr, mr->ms_l1.ta, VTY_NEWLINE);
	if (mr->flags & MEAS_REP_F_DL_VALID)
		meas_rep_dump_uni_vty(vty, &mr->dl, prefix, "dl");
	meas_rep_dump_uni_vty(vty, &mr->ul, prefix, "ul");
}

static inline void print_all_trx_ext(struct vty *vty, bool show_connected)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts = NULL;
	uint8_t bts_nr;
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		uint8_t trx_nr;
		bts = gsm_bts_num(net, bts_nr);
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++)
			trx_dump_vty(vty, gsm_bts_trx_num(bts, trx_nr), false, show_connected);
	}
}

DEFUN(show_trx_con,
      show_trx_con_cmd,
      "show trx (connected|disconnected)",
      SHOW_STR "Display information about a TRX\n"
      "Show TRX with RSL connected\n"
      "Show TRX with RSL disconnected\n")
{
	if (!strcmp(argv[0], "connected"))
		print_all_trx_ext(vty, true);
	else
		print_all_trx_ext(vty, false);

	return CMD_SUCCESS;
}

static void lchan_dump_full_vty(struct vty *vty, struct gsm_lchan *lchan)
{
	int idx;

	vty_out(vty, "BTS %u, TRX %u, Timeslot %u, Lchan %u: Type %s%s",
		lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
		lchan->nr, gsm_lchant_name(lchan->type), VTY_NEWLINE);
	vty_out_dyn_ts_details(vty, lchan->ts);
	vty_out(vty, "  Connection: %u, State: %s%s%s%s",
		lchan->conn ? 1: 0, lchan_state_name(lchan),
		lchan->fi && lchan->fi->state == LCHAN_ST_BORKEN ? " Error reason: " : "",
		lchan->fi && lchan->fi->state == LCHAN_ST_BORKEN ? lchan->last_error : "",
		VTY_NEWLINE);
	vty_out(vty, "  BS Power: %u dBm, MS Power: %u dBm%s",
		lchan->ts->trx->nominal_power - lchan->ts->trx->max_power_red
		- lchan->bs_power*2,
		ms_pwr_dbm(lchan->ts->trx->bts->band, lchan->ms_power),
		VTY_NEWLINE);
	vty_out(vty, "  Channel Mode / Codec: %s%s",
		gsm48_chan_mode_name(lchan->tch_mode),
		VTY_NEWLINE);
	if (lchan->conn && lchan->conn->bsub) {
		vty_out(vty, "  Subscriber:%s", VTY_NEWLINE);
		bsc_subscr_dump_vty(vty, lchan->conn->bsub);
	} else
		vty_out(vty, "  No Subscriber%s", VTY_NEWLINE);
	if (is_ipaccess_bts(lchan->ts->trx->bts)) {
		struct in_addr ia;
		if (lchan->abis_ip.bound_ip) {
			ia.s_addr = htonl(lchan->abis_ip.bound_ip);
			vty_out(vty, "  Bound IP: %s Port %u RTP_TYPE2=%u CONN_ID=%u%s",
				inet_ntoa(ia), lchan->abis_ip.bound_port,
				lchan->abis_ip.rtp_payload2, lchan->abis_ip.conn_id,
				VTY_NEWLINE);
		}
		if (lchan->abis_ip.connect_ip) {
			ia.s_addr = htonl(lchan->abis_ip.connect_ip);
			vty_out(vty, "  Conn. IP: %s Port %u RTP_TYPE=%u SPEECH_MODE=0x%02x%s",
				inet_ntoa(ia), lchan->abis_ip.connect_port,
				lchan->abis_ip.rtp_payload, lchan->abis_ip.speech_mode,
				VTY_NEWLINE);
		}

	}

	/* we want to report the last measurement report */
	idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
			       lchan->meas_rep_idx, 1);
	meas_rep_dump_vty(vty, &lchan->meas_rep[idx], "  ");
}

static void lchan_dump_short_vty(struct vty *vty, struct gsm_lchan *lchan)
{
	struct gsm_meas_rep *mr;
	int idx;

	/* we want to report the last measurement report */
	idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
			       lchan->meas_rep_idx, 1);
	mr =  &lchan->meas_rep[idx];

	vty_out(vty, "BTS %u, TRX %u, Timeslot %u %s",
		lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
		gsm_pchan_name(lchan->ts->pchan_on_init));
	vty_out_dyn_ts_status(vty, lchan->ts);
	vty_out(vty, ", Lchan %u, Type %s, State %s - "
		"L1 MS Power: %u dBm RXL-FULL-dl: %4d dBm RXL-FULL-ul: %4d dBm%s",
		lchan->nr,
		gsm_lchant_name(lchan->type), lchan_state_name(lchan),
		mr->ms_l1.pwr,
		rxlev2dbm(mr->dl.full.rx_lev),
		rxlev2dbm(mr->ul.full.rx_lev),
		VTY_NEWLINE);
}


static int dump_lchan_trx_ts(struct gsm_bts_trx_ts *ts, struct vty *vty,
			     void (*dump_cb)(struct vty *, struct gsm_lchan *),
			     bool all)
{
	struct gsm_lchan *lchan;
	ts_for_each_lchan(lchan, ts) {
		if (lchan_state_is(lchan, LCHAN_ST_UNUSED) && all == false)
			continue;
		dump_cb(vty, lchan);
	}

	return CMD_SUCCESS;
}

static int dump_lchan_trx(struct gsm_bts_trx *trx, struct vty *vty,
			  void (*dump_cb)(struct vty *, struct gsm_lchan *),
			  bool all)
{
	int ts_nr;

	for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[ts_nr];
		dump_lchan_trx_ts(ts, vty, dump_cb, all);
	}

	return CMD_SUCCESS;
}

static int dump_lchan_bts(struct gsm_bts *bts, struct vty *vty,
			  void (*dump_cb)(struct vty *, struct gsm_lchan *),
			  bool all)
{
	int trx_nr;

	for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
		struct gsm_bts_trx *trx = gsm_bts_trx_num(bts, trx_nr);
		dump_lchan_trx(trx, vty, dump_cb, all);
	}

	return CMD_SUCCESS;
}

static int lchan_summary(struct vty *vty, int argc, const char **argv,
			 void (*dump_cb)(struct vty *, struct gsm_lchan *),
			 bool all)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts = NULL;
	struct gsm_bts_trx *trx = NULL;
	struct gsm_bts_trx_ts *ts = NULL;
	struct gsm_lchan *lchan;
	int bts_nr, trx_nr, ts_nr, lchan_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS %s%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);

		if (argc == 1)
			return dump_lchan_bts(bts, vty, dump_cb, all);
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX %s%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx = gsm_bts_trx_num(bts, trx_nr);

		if (argc == 2)
			return dump_lchan_trx(trx, vty, dump_cb, all);
	}
	if (argc >= 3) {
		ts_nr = atoi(argv[2]);
		if (ts_nr >= TRX_NR_TS) {
			vty_out(vty, "%% can't find TS %s%s", argv[2],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		ts = &trx->ts[ts_nr];

		if (argc == 3)
			return dump_lchan_trx_ts(ts, vty, dump_cb, all);
	}
	if (argc >= 4) {
		lchan_nr = atoi(argv[3]);
		if (lchan_nr >= TS_MAX_LCHAN) {
			vty_out(vty, "%% can't find LCHAN %s%s", argv[3],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		lchan = &ts->lchan[lchan_nr];
		dump_cb(vty, lchan);
		return CMD_SUCCESS;
	}


	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(net, bts_nr);
		dump_lchan_bts(bts, vty, dump_cb, all);
	}

	return CMD_SUCCESS;
}


DEFUN(show_lchan,
      show_lchan_cmd,
      "show lchan [<0-255>] [<0-255>] [<0-7>] [<0-7>]",
	SHOW_STR "Display information about a logical channel\n"
	BTS_TRX_TS_LCHAN_STR)
{
	return lchan_summary(vty, argc, argv, lchan_dump_full_vty, true);
}

DEFUN(show_lchan_summary,
      show_lchan_summary_cmd,
      "show lchan summary [<0-255>] [<0-255>] [<0-7>] [<0-7>]",
	SHOW_STR "Display information about a logical channel\n"
        "Short summary (used lchans)\n"
	BTS_TRX_TS_LCHAN_STR)
{
	return lchan_summary(vty, argc, argv, lchan_dump_short_vty, false);
}

DEFUN(show_lchan_summary_all,
      show_lchan_summary_all_cmd,
      "show lchan summary-all [<0-255>] [<0-255>] [<0-7>] [<0-7>]",
	SHOW_STR "Display information about a logical channel\n"
        "Short summary (all lchans)\n"
	BTS_TRX_TS_LCHAN_STR)
{
	return lchan_summary(vty, argc, argv, lchan_dump_short_vty, true);
}

static void dump_one_subscr_conn(struct vty *vty, const struct gsm_subscriber_connection *conn)
{
	vty_out(vty, "conn ID=%u, MSC=%u, hodec2_fail=%d, mgw_ep=%s%s",
		conn->sccp.conn_id, conn->sccp.msc->nr, conn->hodec2.failures,
		osmo_mgcpc_ep_name(conn->user_plane.mgw_endpoint), VTY_NEWLINE);
	if (conn->lcls.global_call_ref_len) {
		vty_out(vty, " LCLS GCR: %s%s",
			osmo_hexdump_nospc(conn->lcls.global_call_ref, conn->lcls.global_call_ref_len),
			VTY_NEWLINE);
		vty_out(vty, " LCLS Config: %s, LCLS Control: %s, LCLS BSS Status: %s%s",
			gsm0808_lcls_config_name(conn->lcls.config),
			gsm0808_lcls_control_name(conn->lcls.control),
			osmo_fsm_inst_state_name(conn->lcls.fi),
			VTY_NEWLINE);
	}
	if (conn->lchan)
		lchan_dump_full_vty(vty, conn->lchan);
	if (conn->assignment.new_lchan)
		lchan_dump_full_vty(vty, conn->assignment.new_lchan);
}

DEFUN(show_subscr_conn,
      show_subscr_conn_cmd,
      "show conns",
      SHOW_STR "Display currently active subscriber connections\n")
{
	struct gsm_subscriber_connection *conn;
	struct gsm_network *net = gsmnet_from_vty(vty);
	bool no_conns = true;
	unsigned int count = 0;

	vty_out(vty, "Active subscriber connections: %s", VTY_NEWLINE);

	llist_for_each_entry(conn, &net->subscr_conns, entry) {
		dump_one_subscr_conn(vty, conn);
		no_conns = false;
		count++;
	}

	if (no_conns)
		vty_out(vty, "None%s", VTY_NEWLINE);

	return CMD_SUCCESS;
}

static int trigger_ho_or_as(struct vty *vty, struct gsm_lchan *from_lchan, struct gsm_bts *to_bts)
{
	if (!to_bts || from_lchan->ts->trx->bts == to_bts) {
		LOGP(DHO, LOGL_NOTICE, "%s Manually triggering Assignment from VTY\n",
		     gsm_lchan_name(from_lchan));
		to_bts = from_lchan->ts->trx->bts;
	} else
		LOGP(DHO, LOGL_NOTICE, "%s (ARFCN %u) --> BTS %u Manually triggering Handover from VTY\n",
		     gsm_lchan_name(from_lchan), from_lchan->ts->trx->arfcn, to_bts->nr);
	{
		struct handover_out_req req = {
			.from_hodec_id = HODEC_USER,
			.old_lchan = from_lchan,
			.target_nik = *bts_ident_key(to_bts),
		};
		handover_request(&req);
	}
	return CMD_SUCCESS;
}

static int ho_or_as(struct vty *vty, const char *argv[], int argc)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_subscriber_connection *conn;
	struct gsm_bts *bts;
	struct gsm_bts *new_bts = NULL;
	unsigned int bts_nr = atoi(argv[0]);
	unsigned int trx_nr = atoi(argv[1]);
	unsigned int ts_nr = atoi(argv[2]);
	unsigned int ss_nr = atoi(argv[3]);
	unsigned int bts_nr_new;
	const char *action;

	if (argc > 4) {
		bts_nr_new = atoi(argv[4]);

		/* Lookup the BTS where we want to handover to */
		llist_for_each_entry(bts, &net->bts_list, list) {
			if (bts->nr == bts_nr_new) {
				new_bts = bts;
				break;
			}
		}

		if (!new_bts) {
			vty_out(vty, "%% Unable to trigger handover, specified bts #%u does not exist %s",
				bts_nr_new, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	action = new_bts ? "handover" : "assignment";

	/* Find the connection/lchan that we want to handover */
	llist_for_each_entry(conn, &net->subscr_conns, entry) {
		struct gsm_bts *bts = conn_get_bts(conn);
		if (!bts)
			continue;
		if (bts->nr == bts_nr &&
		    conn->lchan->ts->trx->nr == trx_nr &&
		    conn->lchan->ts->nr == ts_nr && conn->lchan->nr == ss_nr) {
			vty_out(vty, "starting %s for lchan %s...%s", action, conn->lchan->name, VTY_NEWLINE);
			lchan_dump_full_vty(vty, conn->lchan);
			return trigger_ho_or_as(vty, conn->lchan, new_bts);
		}
	}

	vty_out(vty, "%% Unable to trigger %s, specified connection (bts=%u,trx=%u,ts=%u,ss=%u) does not exist%s",
		action, bts_nr, trx_nr, ts_nr, ss_nr, VTY_NEWLINE);

	return CMD_WARNING;
}

#define MANUAL_HANDOVER_STR "Manually trigger handover (for debugging)\n"
#define MANUAL_ASSIGNMENT_STR "Manually trigger assignment (for debugging)\n"

DEFUN(handover_subscr_conn,
      handover_subscr_conn_cmd,
      "bts <0-255> trx <0-255> timeslot <0-7> sub-slot <0-7> handover <0-255>",
      BTS_NR_TRX_TS_SS_STR2
      MANUAL_HANDOVER_STR
      "New " BTS_NR_STR)
{
	return ho_or_as(vty, argv, argc);
}

DEFUN(assignment_subscr_conn,
      assignment_subscr_conn_cmd,
      "bts <0-255> trx <0-255> timeslot <0-7> sub-slot <0-7> assignment",
      BTS_NR_TRX_TS_SS_STR2
      MANUAL_ASSIGNMENT_STR)
{
	return ho_or_as(vty, argv, argc);
}

static struct gsm_lchan *find_used_voice_lchan(struct vty *vty, int random_idx)
{
	struct gsm_bts *bts;
	struct gsm_network *network = gsmnet_from_vty(vty);

	while (1) {
		int count = 0;
		llist_for_each_entry(bts, &network->bts_list, list) {
			struct gsm_bts_trx *trx;

			llist_for_each_entry(trx, &bts->trx_list, list) {
				int i;
				for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
					struct gsm_bts_trx_ts *ts = &trx->ts[i];
					struct gsm_lchan *lchan;

					if (ts->fi->state != TS_ST_IN_USE)
						continue;

					ts_for_each_lchan(lchan, ts) {
						if (lchan_state_is(lchan, LCHAN_ST_ESTABLISHED)
						    && (lchan->type == GSM_LCHAN_TCH_F
							|| lchan->type == GSM_LCHAN_TCH_H)) {

							if (count == random_idx) {
								vty_out(vty, "Found voice call: %s%s",
									gsm_lchan_name(lchan),
									VTY_NEWLINE);
								lchan_dump_full_vty(vty, lchan);
								return lchan;
							}
							count ++;
						}
					}
				}
			}
		}

		if (!count)
			break;
		/* there are used lchans, but random_idx is > count. Iterate again. */
		random_idx %= count;
	}

	vty_out(vty, "%% Cannot find any ongoing voice calls%s", VTY_NEWLINE);
	return NULL;
}

static struct gsm_bts *find_other_bts_with_free_slots(struct vty *vty, struct gsm_bts *not_this_bts,
						      enum gsm_chan_t free_type)
{
	struct gsm_bts *bts;
	struct gsm_network *network = gsmnet_from_vty(vty);

	llist_for_each_entry(bts, &network->bts_list, list) {
		struct gsm_bts_trx *trx;

		if (bts == not_this_bts)
			continue;

		llist_for_each_entry(trx, &bts->trx_list, list) {
			struct gsm_lchan *lchan = lchan_select_by_type(bts, free_type);
			if (!lchan)
				continue;

			vty_out(vty, "Found unused %s slot: %s%s",
				gsm_lchant_name(free_type), gsm_lchan_name(lchan), VTY_NEWLINE);
			lchan_dump_full_vty(vty, lchan);
			return bts;
		}
	}
	vty_out(vty, "%% Cannot find any BTS (other than BTS %u) with free %s lchan%s",
		not_this_bts? not_this_bts->nr : 255, gsm_lchant_name(free_type), VTY_NEWLINE);
	return NULL;
}

DEFUN(handover_any, handover_any_cmd,
      "handover any",
      MANUAL_HANDOVER_STR
      "Pick any actively used TCH/F or TCH/H lchan and handover to any other BTS."
      " This is likely to fail if not all BTS are guaranteed to be reachable by the MS.\n")
{
	struct gsm_lchan *from_lchan;
	struct gsm_bts *to_bts;

	from_lchan = find_used_voice_lchan(vty, random());
	if (!from_lchan)
		return CMD_WARNING;

	to_bts = find_other_bts_with_free_slots(vty, from_lchan->ts->trx->bts, from_lchan->type);
	if (!to_bts)
		return CMD_WARNING;

	return trigger_ho_or_as(vty, from_lchan, to_bts);
}

DEFUN(assignment_any, assignment_any_cmd,
      "assignment any",
      MANUAL_ASSIGNMENT_STR
      "Pick any actively used TCH/F or TCH/H lchan and re-assign within the same BTS."
      " This will fail if no lchans of the same type are available besides the used one.\n")
{
	struct gsm_lchan *from_lchan;

	from_lchan = find_used_voice_lchan(vty, random());
	if (!from_lchan)
		return CMD_WARNING;

	return trigger_ho_or_as(vty, from_lchan, NULL);
}

DEFUN(handover_any_to_arfcn_bsic, handover_any_to_arfcn_bsic_cmd,
      "handover any to " NEIGHBOR_IDENT_VTY_KEY_PARAMS,
      MANUAL_HANDOVER_STR
      "Pick any actively used TCH/F or TCH/H lchan to handover to another cell."
      " This is likely to fail outside of a lab setup where you are certain that"
      " all MS are able to see the target cell.\n"
      "'to'\n"
      NEIGHBOR_IDENT_VTY_KEY_DOC)
{
	struct handover_out_req req;
	struct gsm_lchan *from_lchan;

	from_lchan = find_used_voice_lchan(vty, random());
	if (!from_lchan)
		return CMD_WARNING;

	req = (struct handover_out_req){
		.from_hodec_id = HODEC_USER,
		.old_lchan = from_lchan,
	};

	if (!neighbor_ident_bts_parse_key_params(vty, from_lchan->ts->trx->bts,
						 argv, &req.target_nik)) {
		vty_out(vty, "%% BTS %u does not know about this neighbor%s",
			from_lchan->ts->trx->bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	handover_request(&req);
	return CMD_SUCCESS;
}

static void paging_dump_vty(struct vty *vty, struct gsm_paging_request *pag)
{
	vty_out(vty, "Paging on BTS %u%s", pag->bts->nr, VTY_NEWLINE);
	bsc_subscr_dump_vty(vty, pag->bsub);
}

static void bts_paging_dump_vty(struct vty *vty, struct gsm_bts *bts)
{
	struct gsm_paging_request *pag;

	if (!bts->paging.bts)
		return;

	llist_for_each_entry(pag, &bts->paging.pending_requests, entry)
		paging_dump_vty(vty, pag);
}

DEFUN(show_paging,
      show_paging_cmd,
      "show paging [<0-255>]",
	SHOW_STR "Display information about paging requests of a BTS\n"
	BTS_NR_STR)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts;
	int bts_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS %s%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);
		bts_paging_dump_vty(vty, bts);

		return CMD_SUCCESS;
	}
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(net, bts_nr);
		bts_paging_dump_vty(vty, bts);
	}

	return CMD_SUCCESS;
}

DEFUN(show_paging_group,
      show_paging_group_cmd,
      "show paging-group <0-255> IMSI",
      SHOW_STR "Display the paging group\n"
      BTS_NR_STR "IMSI\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts;
	unsigned int page_group;
	int bts_nr = atoi(argv[0]);

	if (bts_nr >= net->num_bts) {
		vty_out(vty, "%% can't find BTS %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(net, bts_nr);
	if (!bts) {
		vty_out(vty, "%% can't find BTS %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	page_group = gsm0502_calc_paging_group(&bts->si_common.chan_desc,
						str_to_imsi(argv[1]));
	vty_out(vty, "%% Paging group for IMSI %" PRIu64 " on BTS #%d is %u%s",
		str_to_imsi(argv[1]), bts->nr,
		page_group, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_neci,
	      cfg_net_neci_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "neci (0|1)",
	      "New Establish Cause Indication\n"
	      "Don't set the NECI bit\n" "Set the NECI bit\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->neci = atoi(argv[0]);
	gsm_net_update_ctype(gsmnet);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_pag_any_tch,
	      cfg_net_pag_any_tch_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "paging any use tch (0|1)",
	      "Assign a TCH when receiving a Paging Any request\n"
	      "Any Channel\n" "Use\n" "TCH\n"
	      "Do not use TCH for Paging Request Any\n"
	      "Do use TCH for Paging Request Any\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->pag_any_tch = atoi(argv[0]);
	gsm_net_update_ctype(gsmnet);
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_net_dtx,
		 cfg_net_dtx_cmd,
		 "dtx-used (0|1)",
		 ".HIDDEN\n""Obsolete\n""Obsolete\n")
{
	vty_out(vty, "%% 'dtx-used' is now deprecated: use dtx * "
		"configuration options of BTS instead%s", VTY_NEWLINE);
       return CMD_SUCCESS;
}

#define NRI_STR "Mapping of Network Resource Indicators to this MSC, for MSC pooling\n"
#define NULL_NRI_STR "Define NULL-NRI values that cause re-assignment of an MS to a different MSC, for MSC pooling.\n"
#define NRI_FIRST_LAST_STR "First value of the NRI value range, should not surpass the configured 'nri bitlen'.\n" \
	"Last value of the NRI value range, should not surpass the configured 'nri bitlen' and be larger than the" \
	" first value; if omitted, apply only the first value.\n"
#define NRI_ARGS_TO_STR_FMT "%s%s%s"
#define NRI_ARGS_TO_STR_ARGS(ARGC, ARGV) ARGV[0], (ARGC>1)? ".." : "", (ARGC>1)? ARGV[1] : ""
#define NRI_WARN(MSC, FORMAT, args...) do { \
		vty_out(vty, "%% Warning: msc %d: " FORMAT "%s", MSC->nr, ##args, VTY_NEWLINE); \
		LOGP(DMSC, LOGL_ERROR, "msc %d: " FORMAT "\n", MSC->nr, ##args); \
	} while (0)

DEFUN_ATTR(cfg_net_nri_bitlen,
	   cfg_net_nri_bitlen_cmd,
	   "nri bitlen <1-15>",
	   NRI_STR
	   "Set number of bits that an NRI has, to extract from TMSI identities (always starting just after the TMSI's most significant octet).\n"
	   "bit count (default: " OSMO_STRINGIFY_VAL(NRI_BITLEN_DEFAULT) ")\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->nri_bitlen = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_nri_null_add,
	   cfg_net_nri_null_add_cmd,
	   "nri null add <0-32767> [<0-32767>]",
	   NRI_STR NULL_NRI_STR "Add NULL-NRI value (or range)\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	int rc;
	const char *message;
	rc = osmo_nri_ranges_vty_add(&message, NULL, bsc_gsmnet->null_nri_ranges, argc, argv,
				     bsc_gsmnet->nri_bitlen);
	if (message) {
		vty_out(vty, "%% %s: " NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	}
	if (rc < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_nri_null_del,
	   cfg_net_nri_null_del_cmd,
	   "nri null del <0-32767> [<0-32767>]",
	   NRI_STR NULL_NRI_STR "Remove NRI value or range from the NRI mapping for this MSC\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	int rc;
	const char *message;
	rc = osmo_nri_ranges_vty_del(&message, NULL, bsc_gsmnet->null_nri_ranges, argc, argv);
	if (message) {
		vty_out(vty, "%% %s: " NRI_ARGS_TO_STR_FMT "%s", message, NRI_ARGS_TO_STR_ARGS(argc, argv),
			VTY_NEWLINE);
	}
	if (rc < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

/* per-BTS configuration */
DEFUN_ATTR(cfg_bts,
	   cfg_bts_cmd,
	   "bts <0-255>",
	   "Select a BTS to configure\n"
	   BTS_NR_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	int bts_nr = atoi(argv[0]);
	struct gsm_bts *bts;

	if (bts_nr > gsmnet->num_bts) {
		vty_out(vty, "%% The next unused BTS number is %u%s",
			gsmnet->num_bts, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (bts_nr == gsmnet->num_bts) {
		/* allocate a new one */
		bts = bsc_bts_alloc_register(gsmnet, GSM_BTS_TYPE_UNKNOWN,
					     HARDCODED_BSIC);
		osmo_stat_item_inc(gsmnet->bsc_statg->items[BSC_STAT_NUM_BTS_TOTAL], 1);
	} else
		bts = gsm_bts_num(gsmnet, bts_nr);

	if (!bts) {
		vty_out(vty, "%% Unable to allocate BTS %u%s",
			gsmnet->num_bts, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->index = bts;
	vty->index_sub = &bts->description;
	vty->node = BTS_NODE;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_type,
	      cfg_bts_type_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "type TYPE", /* dynamically created */
	      "Set the BTS type\n" "Type\n")
{
	struct gsm_bts *bts = vty->index;
	int rc;

	rc = gsm_set_bts_type(bts, str2btstype(argv[0]));
	if (rc == -EBUSY)
		vty_out(vty, "%% Changing the type of an existing BTS is not supported.%s",
			VTY_NEWLINE);
	if (rc < 0)
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_band,
	      cfg_bts_band_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "band BAND",
	      "Set the frequency band of this BTS\n" "Frequency band\n")
{
	struct gsm_bts *bts = vty->index;
	int band = gsm_band_parse(argv[0]);

	if (band < 0) {
		vty_out(vty, "%% BAND %d is not a valid GSM band%s",
			band, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->band = band;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_dtxu,
	      cfg_bts_dtxu_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "dtx uplink [force]",
	      "Configure discontinuous transmission\n"
	      "Enable Uplink DTX for this BTS\n"
	      "MS 'shall' use DTXu instead of 'may' use (might not be supported by "
	      "older phones).\n")
{
	struct gsm_bts *bts = vty->index;

	bts->dtxu = (argc > 0) ? GSM48_DTX_SHALL_BE_USED : GSM48_DTX_MAY_BE_USED;
	if (!is_ipaccess_bts(bts))
		vty_out(vty, "%% DTX enabled on non-IP BTS: this configuration "
			"neither supported nor tested!%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_no_dtxu,
	      cfg_bts_no_dtxu_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "no dtx uplink",
	      NO_STR "Configure discontinuous transmission\n"
	      "Disable Uplink DTX for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	bts->dtxu = GSM48_DTX_SHALL_NOT_BE_USED;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_dtxd,
	      cfg_bts_dtxd_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "dtx downlink",
	      "Configure discontinuous transmission\n"
	      "Enable Downlink DTX for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	bts->dtxd = true;
	if (!is_ipaccess_bts(bts))
		vty_out(vty, "%% DTX enabled on non-IP BTS: this configuration "
			"neither supported nor tested!%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_no_dtxd,
	      cfg_bts_no_dtxd_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "no dtx downlink",
	      NO_STR "Configure discontinuous transmission\n"
	      "Disable Downlink DTX for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	bts->dtxd = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_ci,
	      cfg_bts_ci_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "cell_identity <0-65535>",
	      "Set the Cell identity of this BTS\n" "Cell Identity\n")
{
	struct gsm_bts *bts = vty->index;
	int ci = atoi(argv[0]);

	if (ci < 0 || ci > 0xffff) {
		vty_out(vty, "%% CI %d is not in the valid range (0-65535)%s",
			ci, VTY_NEWLINE);
		return CMD_WARNING;
	}
	bts->cell_identity = ci;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_lac,
	      cfg_bts_lac_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "location_area_code <0-65535>",
	      "Set the Location Area Code (LAC) of this BTS\n" "LAC\n")
{
	struct gsm_bts *bts = vty->index;
	int lac = atoi(argv[0]);

	if (lac < 0 || lac > 0xffff) {
		vty_out(vty, "%% LAC %d is not in the valid range (0-65535)%s",
			lac, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (lac == GSM_LAC_RESERVED_DETACHED || lac == GSM_LAC_RESERVED_ALL_BTS) {
		vty_out(vty, "%% LAC %d is reserved by GSM 04.08%s",
			lac, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->location_area_code = lac;

	return CMD_SUCCESS;
}


/* compatibility wrapper for old config files */
DEFUN_HIDDEN(cfg_bts_tsc,
      cfg_bts_tsc_cmd,
      "training_sequence_code <0-7>",
      "Set the Training Sequence Code (TSC) of this BTS\n" "TSC\n")
{
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_bsic,
	      cfg_bts_bsic_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "base_station_id_code <0-63>",
	      "Set the Base Station Identity Code (BSIC) of this BTS\n"
	      "BSIC of this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	int bsic = atoi(argv[0]);

	if (bsic < 0 || bsic > 0x3f) {
		vty_out(vty, "%% BSIC %d is not in the valid range (0-255)%s",
			bsic, VTY_NEWLINE);
		return CMD_WARNING;
	}
	bts->bsic = bsic;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_unit_id,
	      cfg_bts_unit_id_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "ipa unit-id <0-65534> <0-255>",
	      "Abis/IP specific options\n"
	      "Set the IPA BTS Unit ID\n"
	      "Unit ID (Site)\n"
	      "Unit ID (BTS)\n")
{
	struct gsm_bts *bts = vty->index;
	int site_id = atoi(argv[0]);
	int bts_id = atoi(argv[1]);

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% BTS is not of ip.access type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->ip_access.site_id = site_id;
	bts->ip_access.bts_id = bts_id;

	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_bts_unit_id,
      cfg_bts_deprecated_unit_id_cmd,
      "ip.access unit_id <0-65534> <0-255>",
      "Abis/IP specific options\n"
      "Set the IPA BTS Unit ID\n"
      "Unit ID (Site)\n"
      "Unit ID (BTS)\n");

DEFUN_USRATTR(cfg_bts_rsl_ip,
	      cfg_bts_rsl_ip_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "ipa rsl-ip A.B.C.D",
	      "Abis/IP specific options\n"
	      "Set the IPA RSL IP Address of the BSC\n"
	      "Destination IP address for RSL connection\n")
{
	struct gsm_bts *bts = vty->index;
	struct in_addr ia;

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% BTS is not of ip.access type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	inet_aton(argv[0], &ia);
	bts->ip_access.rsl_ip = ntohl(ia.s_addr);

	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_bts_rsl_ip,
      cfg_bts_deprecated_rsl_ip_cmd,
      "ip.access rsl-ip A.B.C.D",
      "Abis/IP specific options\n"
      "Set the IPA RSL IP Address of the BSC\n"
      "Destination IP address for RSL connection\n");

#define NOKIA_STR "Nokia *Site related commands\n"

DEFUN_USRATTR(cfg_bts_nokia_site_skip_reset,
	      cfg_bts_nokia_site_skip_reset_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "nokia_site skip-reset (0|1)",
	      NOKIA_STR
	      "Skip the reset step during bootstrap process of this BTS\n"
	      "Do NOT skip the reset\n" "Skip the reset\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->type != GSM_BTS_TYPE_NOKIA_SITE) {
		vty_out(vty, "%% BTS is not of Nokia *Site type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->nokia.skip_reset = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_nokia_site_no_loc_rel_cnf,
	   cfg_bts_nokia_site_no_loc_rel_cnf_cmd,
	   "nokia_site no-local-rel-conf (0|1)",
	   NOKIA_STR
	   "Do not wait for RELease CONFirm message when releasing channel locally\n"
	   "Wait for RELease CONFirm\n" "Do not wait for RELease CONFirm\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;

	if (!is_nokia_bts(bts)) {
		vty_out(vty, "%% BTS is not of Nokia *Site type%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->nokia.no_loc_rel_cnf = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_nokia_site_bts_reset_timer_cnf,
	   cfg_bts_nokia_site_bts_reset_timer_cnf_cmd,
	   "nokia_site bts-reset-timer  <15-100>",
	   NOKIA_STR
	   "The amount of time (in sec.) between BTS_RESET is sent,\n"
	   "and the BTS is being bootstrapped.\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;

	if (!is_nokia_bts(bts)) {
		vty_out(vty, "%% BTS is not of Nokia *Site type%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->nokia.bts_reset_timer_cnf = atoi(argv[0]);

	return CMD_SUCCESS;
}
#define OML_STR	"Organization & Maintenance Link\n"
#define IPA_STR "A-bis/IP Specific Options\n"

DEFUN_USRATTR(cfg_bts_stream_id,
	      cfg_bts_stream_id_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "oml ipa stream-id <0-255> line E1_LINE",
	      OML_STR IPA_STR
	      "Set the ipa Stream ID of the OML link of this BTS\n" "Stream Identifier\n"
	      "Virtual E1 Line Number\n" "Virtual E1 Line Number\n")
{
	struct gsm_bts *bts = vty->index;
	int stream_id = atoi(argv[0]), linenr = atoi(argv[1]);

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% BTS is not of ip.access type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->oml_tei = stream_id;
	/* This is used by e1inp_bind_ops callback for each BTS model. */
	bts->oml_e1_link.e1_nr = linenr;

	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_bts_stream_id,
      cfg_bts_deprecated_stream_id_cmd,
      "oml ip.access stream_id <0-255> line E1_LINE",
	OML_STR IPA_STR
      "Set the ip.access Stream ID of the OML link of this BTS\n"
      "Stream Identifier\n" "Virtual E1 Line Number\n" "Virtual E1 Line Number\n");

#define OML_E1_STR OML_STR "OML E1/T1 Configuration\n"

/* NOTE: This requires a full restart as bsc_network_configure() is executed
 * only once on startup from osmo_bsc_main.c */
DEFUN(cfg_bts_oml_e1,
      cfg_bts_oml_e1_cmd,
      "oml e1 line E1_LINE timeslot <1-31> sub-slot (0|1|2|3|full)",
	OML_E1_STR
      "E1/T1 line number to be used for OML\n"
      "E1/T1 line number to be used for OML\n"
      "E1/T1 timeslot to be used for OML\n"
      "E1/T1 timeslot to be used for OML\n"
      "E1/T1 sub-slot to be used for OML\n"
      "Use E1/T1 sub-slot 0\n"
      "Use E1/T1 sub-slot 1\n"
      "Use E1/T1 sub-slot 2\n"
      "Use E1/T1 sub-slot 3\n"
      "Use full E1 slot 3\n"
      )
{
	struct gsm_bts *bts = vty->index;

	parse_e1_link(&bts->oml_e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_oml_e1_tei,
	      cfg_bts_oml_e1_tei_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "oml e1 tei <0-63>",
	      OML_E1_STR
	      "Set the TEI to be used for OML\n"
	      "TEI Number\n")
{
	struct gsm_bts *bts = vty->index;

	bts->oml_tei = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_challoc,
	   cfg_bts_challoc_cmd,
	   "channel allocator (ascending|descending)",
	   "Channel Allocator\n" "Channel Allocator\n"
	   "Allocate Timeslots and Transceivers in ascending order\n"
	   "Allocate Timeslots and Transceivers in descending order\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;

	if (!strcmp(argv[0], "ascending"))
		bts->chan_alloc_reverse = 0;
	else
		bts->chan_alloc_reverse = 1;

	return CMD_SUCCESS;
}

#define RACH_STR "Random Access Control Channel\n"

DEFUN_USRATTR(cfg_bts_rach_tx_integer,
	      cfg_bts_rach_tx_integer_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "rach tx integer <0-15>",
	      RACH_STR
	      "Set the raw tx integer value in RACH Control parameters IE\n"
	      "Set the raw tx integer value in RACH Control parameters IE\n"
	      "Raw tx integer value in RACH Control parameters IE\n")
{
	struct gsm_bts *bts = vty->index;
	bts->si_common.rach_control.tx_integer = atoi(argv[0]) & 0xf;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rach_max_trans,
	      cfg_bts_rach_max_trans_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "rach max transmission (1|2|4|7)",
	      RACH_STR
	      "Set the maximum number of RACH burst transmissions\n"
	      "Set the maximum number of RACH burst transmissions\n"
	      "Maximum number of 1 RACH burst transmissions\n"
	      "Maximum number of 2 RACH burst transmissions\n"
	      "Maximum number of 4 RACH burst transmissions\n"
	      "Maximum number of 7 RACH burst transmissions\n")
{
	struct gsm_bts *bts = vty->index;
	bts->si_common.rach_control.max_trans = rach_max_trans_val2raw(atoi(argv[0]));
	return CMD_SUCCESS;
}

#define REP_ACCH_STR "FACCH/SACCH repetition\n"

DEFUN_USRATTR(cfg_bts_rep_dl_facch,
	      cfg_bts_rep_dl_facch_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "repeat dl-facch (command|all)",
	      REP_ACCH_STR
	      "Enable DL-FACCH repetition for this BTS\n"
	      "command LAPDm frames only\n"
	      "all LAPDm frames\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->model->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% repeated ACCH not supported by BTS %u%s",
			bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "command")) {
	        bts->repeated_acch_policy.dl_facch_cmd = true;
	        bts->repeated_acch_policy.dl_facch_all = false;
	} else {
	        bts->repeated_acch_policy.dl_facch_cmd = true;
	        bts->repeated_acch_policy.dl_facch_all = true;
	}
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rep_no_dl_facch,
	      cfg_bts_rep_no_dl_facch_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "no repeat dl-facch",
	      NO_STR REP_ACCH_STR
	      "Disable DL-FACCH repetition for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	bts->repeated_acch_policy.dl_facch_cmd = false;
	bts->repeated_acch_policy.dl_facch_all = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rep_ul_dl_sacch,
	      cfg_bts_rep_ul_dl_sacch_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "repeat (ul-sacch|dl-sacch)",
	      REP_ACCH_STR
	      "Enable UL-SACCH repetition for this BTS\n"
	      "Enable DL-SACCH repetition for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->model->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% repeated ACCH not supported by BTS %u%s",
			bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (strcmp(argv[0], "ul-sacch") == 0)
		bts->repeated_acch_policy.ul_sacch = true;
	else
		bts->repeated_acch_policy.dl_sacch = true;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rep_no_ul_dl_sacch,
	      cfg_bts_rep_no_ul_dl_sacch_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "no repeat (ul-sacch|dl-sacch)",
	      NO_STR REP_ACCH_STR
	      "Disable UL-SACCH repetition for this BTS\n"
	      "Disable DL-SACCH repetition for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	if (strcmp(argv[0], "ul-sacch") == 0)
		bts->repeated_acch_policy.ul_sacch = false;
	else
		bts->repeated_acch_policy.dl_sacch = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rep_rxqual,
	      cfg_bts_rep_rxqual_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "repeat rxqual (0|1|2|3|4|5|6|7)",
	      REP_ACCH_STR
	      "Set UL-SACCH/DL-FACCH rxqual threshold-ber\n"
	      "0 disabled (always on)\n"
	      "1 BER >= 0.2%\n"
	      "2 BER >= 0.4%\n"
	      "3 BER >= 0.8%\n"
	      "4 BER >= 1.6% (default)\n"
	      "5 BER >= 3.2%\n"
	      "6 BER >= 6.4%\n"
	      "7 BER >= 12.8%\n")
	      /* See also: GSM 05.08, section 8.2.4 */
{
	struct gsm_bts *bts = vty->index;

	if (bts->model->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% repeated ACCH not supported by BTS %u%s",
			bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* See also: GSM 05.08, section 8.2.4 */
	bts->repeated_acch_policy.rxqual = atoi(argv[0]);

	return CMD_SUCCESS;
}


#define CD_STR "Channel Description\n"

DEFUN_USRATTR(cfg_bts_chan_desc_att,
	      cfg_bts_chan_desc_att_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "channel-description attach (0|1)",
	      CD_STR
	      "Set if attachment is required\n"
	      "Attachment is NOT required\n"
	      "Attachment is required (standard)\n")
{
	struct gsm_bts *bts = vty->index;
	bts->si_common.chan_desc.att = atoi(argv[0]);
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_bts_chan_desc_att,
		 cfg_bts_chan_dscr_att_cmd,
		 "channel-descrption attach (0|1)",
		 CD_STR
		 "Set if attachment is required\n"
		 "Attachment is NOT required\n"
		 "Attachment is required (standard)\n");

DEFUN_USRATTR(cfg_bts_chan_desc_bs_pa_mfrms,
	      cfg_bts_chan_desc_bs_pa_mfrms_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "channel-description bs-pa-mfrms <2-9>",
	      CD_STR
	      "Set number of multiframe periods for paging groups\n"
	      "Number of multiframe periods for paging groups\n")
{
	struct gsm_bts *bts = vty->index;
	int bs_pa_mfrms = atoi(argv[0]);

	bts->si_common.chan_desc.bs_pa_mfrms = bs_pa_mfrms - 2;
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_bts_chan_desc_bs_pa_mfrms,
		 cfg_bts_chan_dscr_bs_pa_mfrms_cmd,
		 "channel-descrption bs-pa-mfrms <2-9>",
		 CD_STR
		 "Set number of multiframe periods for paging groups\n"
		 "Number of multiframe periods for paging groups\n");

DEFUN_USRATTR(cfg_bts_chan_desc_bs_ag_blks_res,
	      cfg_bts_chan_desc_bs_ag_blks_res_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "channel-description bs-ag-blks-res <0-7>",
	      CD_STR
	      "Set number of blocks reserved for access grant\n"
	      "Number of blocks reserved for access grant\n")
{
	struct gsm_bts *bts = vty->index;
	int bs_ag_blks_res = atoi(argv[0]);

	bts->si_common.chan_desc.bs_ag_blks_res = bs_ag_blks_res;
	return CMD_SUCCESS;
}
ALIAS_DEPRECATED(cfg_bts_chan_desc_bs_ag_blks_res,
		 cfg_bts_chan_dscr_bs_ag_blks_res_cmd,
		 "channel-descrption bs-ag-blks-res <0-7>",
		 CD_STR
		 "Set number of blocks reserved for access grant\n"
		 "Number of blocks reserved for access grant\n");

#define CCCH_STR "Common Control Channel\n"

DEFUN_USRATTR(cfg_bts_ccch_load_ind_thresh,
	      cfg_bts_ccch_load_ind_thresh_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "ccch load-indication-threshold <0-100>",
	      CCCH_STR
	      "Percentage of CCCH load at which BTS sends RSL CCCH LOAD IND\n"
	      "CCCH Load Threshold in percent (Default: 10)\n")
{
	struct gsm_bts *bts = vty->index;
	bts->ccch_load_ind_thresh = atoi(argv[0]);
	return CMD_SUCCESS;
}

#define NM_STR "Network Management\n"

DEFUN_USRATTR(cfg_bts_rach_nm_b_thresh,
	      cfg_bts_rach_nm_b_thresh_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "rach nm busy threshold <0-255>",
	      RACH_STR NM_STR
	      "Set the NM Busy Threshold\n"
	      "Set the NM Busy Threshold\n"
	      "NM Busy Threshold in dB\n")
{
	struct gsm_bts *bts = vty->index;
	bts->rach_b_thresh = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rach_nm_ldavg,
	      cfg_bts_rach_nm_ldavg_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "rach nm load average <0-65535>",
	      RACH_STR NM_STR
	      "Set the NM Loadaverage Slots value\n"
	      "Set the NM Loadaverage Slots value\n"
	      "NM Loadaverage Slots value\n")
{
	struct gsm_bts *bts = vty->index;
	bts->rach_ldavg_slots = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_cell_barred,
	      cfg_bts_cell_barred_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "cell barred (0|1)",
	      "Should this cell be barred from access?\n"
	      "Should this cell be barred from access?\n"
	      "Cell should NOT be barred\n"
	      "Cell should be barred\n")

{
	struct gsm_bts *bts = vty->index;

	bts->si_common.rach_control.cell_bar = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rach_ec_allowed,
	      cfg_bts_rach_ec_allowed_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "rach emergency call allowed (0|1)",
	      RACH_STR
	      "Should this cell allow emergency calls?\n"
	      "Should this cell allow emergency calls?\n"
	      "Should this cell allow emergency calls?\n"
	      "Do NOT allow emergency calls\n"
	      "Allow emergency calls\n")
{
	struct gsm_bts *bts = vty->index;

	if (atoi(argv[0]) == 0)
		bts->si_common.rach_control.t2 |= 0x4;
	else
		bts->si_common.rach_control.t2 &= ~0x4;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rach_ac_class,
	      cfg_bts_rach_ac_class_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "rach access-control-class (0|1|2|3|4|5|6|7|8|9|11|12|13|14|15) (barred|allowed)",
	      RACH_STR
	      "Set access control class\n"
	      "Access control class 0\n"
	      "Access control class 1\n"
	      "Access control class 2\n"
	      "Access control class 3\n"
	      "Access control class 4\n"
	      "Access control class 5\n"
	      "Access control class 6\n"
	      "Access control class 7\n"
	      "Access control class 8\n"
	      "Access control class 9\n"
	      "Access control class 11 for PLMN use\n"
	      "Access control class 12 for security services\n"
	      "Access control class 13 for public utilities (e.g. water/gas suppliers)\n"
	      "Access control class 14 for emergency services\n"
	      "Access control class 15 for PLMN staff\n"
	      "barred to use access control class\n"
	      "allowed to use access control class\n")
{
	struct gsm_bts *bts = vty->index;

	uint8_t control_class;
	uint8_t allowed = 0;

	if (strcmp(argv[1], "allowed") == 0)
		allowed = 1;

	control_class = atoi(argv[0]);
	if (control_class < 8)
		if (allowed)
			bts->si_common.rach_control.t3 &= ~(0x1 << control_class);
		else
			bts->si_common.rach_control.t3 |= (0x1 << control_class);
	else
		if (allowed)
			bts->si_common.rach_control.t2 &= ~(0x1 << (control_class - 8));
		else
			bts->si_common.rach_control.t2 |= (0x1 << (control_class - 8));

	if (control_class < 10)
		acc_mgr_perm_subset_changed(&bts->acc_mgr, &bts->si_common.rach_control);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_ms_max_power,
	      cfg_bts_ms_max_power_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "ms max power <0-40>",
	      "MS Options\n"
	      "Maximum transmit power of the MS\n"
	      "Maximum transmit power of the MS\n"
	      "Maximum transmit power of the MS in dBm\n")
{
	struct gsm_bts *bts = vty->index;

	bts->ms_max_power = atoi(argv[0]);

	return CMD_SUCCESS;
}

#define CELL_STR "Cell Parameters\n"

DEFUN_USRATTR(cfg_bts_cell_resel_hyst,
	      cfg_bts_cell_resel_hyst_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "cell reselection hysteresis <0-14>",
	      CELL_STR "Cell re-selection parameters\n"
	      "Cell Re-Selection Hysteresis in dB\n"
	      "Cell Re-Selection Hysteresis in dB\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_sel_par.cell_resel_hyst = atoi(argv[0])/2;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_rxlev_acc_min,
	      cfg_bts_rxlev_acc_min_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "rxlev access min <0-63>",
	      "Minimum RxLev needed for cell access\n"
	      "Minimum RxLev needed for cell access\n"
	      "Minimum RxLev needed for cell access\n"
	      "Minimum RxLev needed for cell access (better than -110dBm)\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_sel_par.rxlev_acc_min = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_cell_bar_qualify,
	      cfg_bts_cell_bar_qualify_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "cell bar qualify (0|1)",
	      CELL_STR "Cell Bar Qualify\n" "Cell Bar Qualify\n"
	      "Set CBQ to 0\n" "Set CBQ to 1\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.cbq = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_cell_resel_ofs,
	      cfg_bts_cell_resel_ofs_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "cell reselection offset <0-126>",
	      CELL_STR "Cell Re-Selection Parameters\n"
	      "Cell Re-Selection Offset (CRO) in dB\n"
	      "Cell Re-Selection Offset (CRO) in dB\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.cell_resel_off = atoi(argv[0])/2;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_temp_ofs,
	      cfg_bts_temp_ofs_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "temporary offset <0-60>",
	      "Cell selection temporary negative offset\n"
	      "Cell selection temporary negative offset\n"
	      "Cell selection temporary negative offset in dB\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.temp_offs = atoi(argv[0])/10;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_temp_ofs_inf,
	      cfg_bts_temp_ofs_inf_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "temporary offset infinite",
	      "Cell selection temporary negative offset\n"
	      "Cell selection temporary negative offset\n"
	      "Sets cell selection temporary negative offset to infinity\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.temp_offs = 7;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_penalty_time,
	      cfg_bts_penalty_time_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "penalty time <20-620>",
	      "Cell selection penalty time\n"
	      "Cell selection penalty time\n"
	      "Cell selection penalty time in seconds (by 20s increments)\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.penalty_time = (atoi(argv[0])-20)/20;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_penalty_time_rsvd,
	      cfg_bts_penalty_time_rsvd_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "penalty time reserved",
	      "Cell selection penalty time\n"
	      "Cell selection penalty time\n"
	      "Set cell selection penalty time to reserved value 31, "
		    "(indicate that CELL_RESELECT_OFFSET is subtracted from C2 "
		    "and TEMPORARY_OFFSET is ignored)\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.penalty_time = 31;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_radio_link_timeout,
	      cfg_bts_radio_link_timeout_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "radio-link-timeout <4-64>",
	      "Radio link timeout criterion (BTS side)\n"
	      "Radio link timeout value (lost SACCH block)\n")
{
	struct gsm_bts *bts = vty->index;

	gsm_bts_set_radio_link_timeout(bts, atoi(argv[0]));

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_radio_link_timeout_inf,
	      cfg_bts_radio_link_timeout_inf_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "radio-link-timeout infinite",
	      "Radio link timeout criterion (BTS side)\n"
	      "Infinite Radio link timeout value (use only for BTS RF testing)\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% infinite radio link timeout not supported by BTS %u%s", bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "%% INFINITE RADIO LINK TIMEOUT, USE ONLY FOR BTS RF TESTING%s", VTY_NEWLINE);
	gsm_bts_set_radio_link_timeout(bts, -1);

	return CMD_SUCCESS;
}

#define GPRS_TEXT	"GPRS Packet Network\n"

#define GPRS_CHECK_ENABLED(bts) \
	do { \
		if (bts->gprs.mode == BTS_GPRS_NONE) { \
			vty_out(vty, "%% GPRS is not enabled on BTS %u%s", \
				bts->nr, VTY_NEWLINE); \
			return CMD_WARNING; \
		} \
	} while (0)

DEFUN_USRATTR(cfg_bts_prs_bvci,
	      cfg_bts_gprs_bvci_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs cell bvci <2-65535>",
	      GPRS_TEXT
	      "GPRS Cell Settings\n"
	      "GPRS BSSGP VC Identifier\n"
	      "GPRS BSSGP VC Identifier\n")
{
	/* ETSI TS 101 343: values 0 and 1 are reserved for signalling and PTM */
	struct gsm_bts *bts = vty->index;

	GPRS_CHECK_ENABLED(bts);

	bts->gprs.cell.bvci = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_nsei,
	      cfg_bts_gprs_nsei_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs nsei <0-65535>",
	      GPRS_TEXT
	      "GPRS NS Entity Identifier\n"
	      "GPRS NS Entity Identifier\n")
{
	struct gsm_bts *bts = vty->index;

	GPRS_CHECK_ENABLED(bts);

	bts->site_mgr->gprs.nse.nsei = atoi(argv[0]);

	return CMD_SUCCESS;
}

#define NSVC_TEXT "Network Service Virtual Connection (NS-VC)\n" \
		"NSVC Logical Number\n"

DEFUN_USRATTR(cfg_bts_gprs_nsvci,
	      cfg_bts_gprs_nsvci_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs nsvc <0-1> nsvci <0-65535>",
	      GPRS_TEXT NSVC_TEXT
	      "NS Virtual Connection Identifier\n"
	      "GPRS NS VC Identifier\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = atoi(argv[0]);

	GPRS_CHECK_ENABLED(bts);

	bts->site_mgr->gprs.nsvc[idx].nsvci = atoi(argv[1]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_nsvc_lport,
	      cfg_bts_gprs_nsvc_lport_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs nsvc <0-1> local udp port <0-65535>",
	      GPRS_TEXT NSVC_TEXT
	      "GPRS NS Local UDP Port\n"
	      "GPRS NS Local UDP Port\n"
	      "GPRS NS Local UDP Port\n"
	      "GPRS NS Local UDP Port Number\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = atoi(argv[0]);

	GPRS_CHECK_ENABLED(bts);

	bts->site_mgr->gprs.nsvc[idx].local_port = atoi(argv[1]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_nsvc_rport,
	      cfg_bts_gprs_nsvc_rport_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs nsvc <0-1> remote udp port <0-65535>",
	      GPRS_TEXT NSVC_TEXT
	      "GPRS NS Remote UDP Port\n"
	      "GPRS NS Remote UDP Port\n"
	      "GPRS NS Remote UDP Port\n"
	      "GPRS NS Remote UDP Port Number\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = atoi(argv[0]);

	GPRS_CHECK_ENABLED(bts);

	/* sockaddr_in and sockaddr_in6 have the port at the same position */
	bts->site_mgr->gprs.nsvc[idx].remote.u.sin.sin_port = htons(atoi(argv[1]));

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_nsvc_rip,
	      cfg_bts_gprs_nsvc_rip_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs nsvc <0-1> remote ip " VTY_IPV46_CMD,
	      GPRS_TEXT NSVC_TEXT
	      "GPRS NS Remote IP Address\n"
	      "GPRS NS Remote IP Address\n"
	      "GPRS NS Remote IPv4 Address\n"
	      "GPRS NS Remote IPv6 Address\n")
{
	struct gsm_bts *bts = vty->index;
	struct osmo_sockaddr_str remote;
	int idx = atoi(argv[0]);
	int ret;

	GPRS_CHECK_ENABLED(bts);

	ret = osmo_sockaddr_str_from_str2(&remote, argv[1]);
	if (ret) {
		vty_out(vty, "%% Invalid IP address %s%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Can't use osmo_sockaddr_str_to_sockaddr() because the port would be overriden */
	bts->site_mgr->gprs.nsvc[idx].remote.u.sas.ss_family = remote.af;
	switch (remote.af) {
	case AF_INET:
		osmo_sockaddr_str_to_in_addr(&remote, &bts->site_mgr->gprs.nsvc[idx].remote.u.sin.sin_addr);
		break;
	case AF_INET6:
		osmo_sockaddr_str_to_in6_addr(&remote, &bts->site_mgr->gprs.nsvc[idx].remote.u.sin6.sin6_addr);
		break;
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_pag_free, cfg_bts_pag_free_cmd,
	   "paging free <-1-1024>",
	   "Paging options\n"
	   "Only page when having a certain amount of free slots\n"
	   "amount of required free paging slots. -1 to disable\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;

	bts->paging.free_chans_need = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_ns_timer,
	      cfg_bts_gprs_ns_timer_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs ns timer " NS_TIMERS " <0-255>",
	      GPRS_TEXT "Network Service\n"
	      "Network Service Timer\n"
	      NS_TIMERS_HELP "Timer Value\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = get_string_value(gprs_ns_timer_strs, argv[0]);
	int val = atoi(argv[1]);

	GPRS_CHECK_ENABLED(bts);

	if (idx < 0 || idx >= ARRAY_SIZE(bts->site_mgr->gprs.nse.timer))
		return CMD_WARNING;

	bts->site_mgr->gprs.nse.timer[idx] = val;

	return CMD_SUCCESS;
}

#define BSSGP_TIMERS "(blocking-timer|blocking-retries|unblocking-retries|reset-timer|reset-retries|suspend-timer|suspend-retries|resume-timer|resume-retries|capability-update-timer|capability-update-retries)"
#define BSSGP_TIMERS_HELP	\
	"Tbvc-block timeout\n"			\
	"Tbvc-block retries\n"			\
	"Tbvc-unblock retries\n"		\
	"Tbvcc-reset timeout\n"			\
	"Tbvc-reset retries\n"			\
	"Tbvc-suspend timeout\n"		\
	"Tbvc-suspend retries\n"		\
	"Tbvc-resume timeout\n"			\
	"Tbvc-resume retries\n"			\
	"Tbvc-capa-update timeout\n"		\
	"Tbvc-capa-update retries\n"

DEFUN_USRATTR(cfg_bts_gprs_cell_timer,
	      cfg_bts_gprs_cell_timer_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs cell timer " BSSGP_TIMERS " <0-255>",
	      GPRS_TEXT "Cell / BSSGP\n"
	      "Cell/BSSGP Timer\n"
	      BSSGP_TIMERS_HELP "Timer Value\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = get_string_value(gprs_bssgp_cfg_strs, argv[0]);
	int val = atoi(argv[1]);

	GPRS_CHECK_ENABLED(bts);

	if (idx < 0 || idx >= ARRAY_SIZE(bts->gprs.cell.timer))
		return CMD_WARNING;

	bts->gprs.cell.timer[idx] = val;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_rac,
	      cfg_bts_gprs_rac_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs routing area <0-255>",
	      GPRS_TEXT
	      "GPRS Routing Area Code\n"
	      "GPRS Routing Area Code\n"
	      "GPRS Routing Area Code\n")
{
	struct gsm_bts *bts = vty->index;

	GPRS_CHECK_ENABLED(bts);

	bts->gprs.rac = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_ctrl_ack,
	      cfg_bts_gprs_ctrl_ack_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "gprs control-ack-type-rach",
	      GPRS_TEXT
	      "Set GPRS Control Ack Type for PACKET CONTROL ACKNOWLEDGMENT message to "
	      "four access bursts format instead of default RLC/MAC control block\n")
{
	struct gsm_bts *bts = vty->index;

	GPRS_CHECK_ENABLED(bts);

	bts->gprs.ctrl_ack_type_use_block = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_ccn_active,
	      cfg_bts_gprs_ccn_active_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "gprs ccn-active (0|1|default)",
	      GPRS_TEXT
	      "Set CCN_ACTIVE in the GPRS Cell Options IE on the BCCH (SI13)\n"
	      "Disable\n" "Enable\n" "Default based on BTS type support\n")
{
	struct gsm_bts *bts = vty->index;

	bts->gprs.ccn.forced_vty = strcmp(argv[0], "default") != 0;

	if (bts->gprs.ccn.forced_vty)
		bts->gprs.ccn.active = argv[0][0] == '1';

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_pwr_ctrl_alpha,
	      cfg_bts_gprs_pwr_ctrl_alpha_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "gprs power-control alpha <0-10>",
	      GPRS_TEXT
	      "GPRS Global Power Control Parameters IE (SI13)\n"
	      "Set alpha\n"
	      "alpha for MS output power control in units of 0.1 (defaults to 0)\n")
{
	struct gsm_bts *bts = vty->index;

	bts->gprs.pwr_ctrl.alpha = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_no_bts_gprs_ctrl_ack,
	      cfg_no_bts_gprs_ctrl_ack_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "no gprs control-ack-type-rach",
	      NO_STR GPRS_TEXT
	      "Set GPRS Control Ack Type for PACKET CONTROL ACKNOWLEDGMENT message to "
	      "default RLC/MAC control block\n")
{
	struct gsm_bts *bts = vty->index;

	GPRS_CHECK_ENABLED(bts);

	bts->gprs.ctrl_ack_type_use_block = true;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_net_ctrl_ord,
	      cfg_bts_gprs_net_ctrl_ord_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "gprs network-control-order (nc0|nc1|nc2)",
	      GPRS_TEXT
	      "GPRS Network Control Order\n"
	      "MS controlled cell re-selection, no measurement reporting\n"
	      "MS controlled cell re-selection, MS sends measurement reports\n"
	      "Network controlled cell re-selection, MS sends measurement reports\n")
{
	struct gsm_bts *bts = vty->index;

	GPRS_CHECK_ENABLED(bts);

	bts->gprs.net_ctrl_ord = atoi(argv[0] + 2);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_mode,
	      cfg_bts_gprs_mode_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "gprs mode (none|gprs|egprs)",
	      GPRS_TEXT
	      "GPRS Mode for this BTS\n"
	      "GPRS Disabled on this BTS\n"
	      "GPRS Enabled on this BTS\n"
	      "EGPRS (EDGE) Enabled on this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	enum bts_gprs_mode mode = bts_gprs_mode_parse(argv[0], NULL);

	if (!bts_gprs_mode_is_compat(bts, mode)) {
		vty_out(vty, "%% This BTS type does not support %s%s", argv[0],
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.mode = mode;

	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_bts_gprs_11bit_rach_support_for_egprs,
	cfg_bts_gprs_11bit_rach_support_for_egprs_cmd,
	"gprs 11bit_rach_support_for_egprs (0|1)",
	GPRS_TEXT "EGPRS Packet Channel Request support\n"
	"Disable EGPRS Packet Channel Request support\n"
	"Enable EGPRS Packet Channel Request support\n")
{
	struct gsm_bts *bts = vty->index;

	vty_out(vty, "%% 'gprs 11bit_rach_support_for_egprs' is now deprecated: "
		"use '[no] gprs egprs-packet-channel-request' instead%s", VTY_NEWLINE);

	bts->gprs.egprs_pkt_chan_request = (argv[0][0] == '1');

	if (bts->gprs.mode == BTS_GPRS_NONE && bts->gprs.egprs_pkt_chan_request) {
		vty_out(vty, "%% (E)GPRS is not enabled (see 'gprs mode')%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (bts->gprs.mode != BTS_GPRS_EGPRS) {
		vty_out(vty, "%% EGPRS Packet Channel Request support requires "
			"EGPRS mode to be enabled (see 'gprs mode')%s", VTY_NEWLINE);
		/* Do not return here, keep the old behaviour. */
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_gprs_egprs_pkt_chan_req,
	      cfg_bts_gprs_egprs_pkt_chan_req_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "gprs egprs-packet-channel-request",
	      GPRS_TEXT "EGPRS Packet Channel Request support")
{
	struct gsm_bts *bts = vty->index;

	if (bts->gprs.mode != BTS_GPRS_EGPRS) {
		vty_out(vty, "%% EGPRS Packet Channel Request support requires "
			"EGPRS mode to be enabled (see 'gprs mode')%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.egprs_pkt_chan_request = true;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_no_gprs_egprs_pkt_chan_req,
	      cfg_bts_no_gprs_egprs_pkt_chan_req_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "no gprs egprs-packet-channel-request",
	      NO_STR GPRS_TEXT "EGPRS Packet Channel Request support")
{
	struct gsm_bts *bts = vty->index;

	if (bts->gprs.mode != BTS_GPRS_EGPRS) {
		vty_out(vty, "%% EGPRS Packet Channel Request support requires "
			"EGPRS mode to be enabled (see 'gprs mode')%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.egprs_pkt_chan_request = false;
	return CMD_SUCCESS;
}

#define SI_TEXT		"System Information Messages\n"
#define SI_TYPE_TEXT "(1|2|3|4|5|6|7|8|9|10|13|16|17|18|19|20|2bis|2ter|2quater|5bis|5ter)"
#define SI_TYPE_HELP 	"System Information Type 1\n"	\
			"System Information Type 2\n"	\
			"System Information Type 3\n"	\
			"System Information Type 4\n"	\
			"System Information Type 5\n"	\
			"System Information Type 6\n"	\
			"System Information Type 7\n"	\
			"System Information Type 8\n"	\
			"System Information Type 9\n"	\
			"System Information Type 10\n"	\
			"System Information Type 13\n"	\
			"System Information Type 16\n"	\
			"System Information Type 17\n"	\
			"System Information Type 18\n"	\
			"System Information Type 19\n"	\
			"System Information Type 20\n"	\
			"System Information Type 2bis\n"	\
			"System Information Type 2ter\n"	\
			"System Information Type 2quater\n"	\
			"System Information Type 5bis\n"	\
			"System Information Type 5ter\n"

DEFUN_USRATTR(cfg_bts_si_mode,
	      cfg_bts_si_mode_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "system-information " SI_TYPE_TEXT " mode (static|computed)",
	      SI_TEXT SI_TYPE_HELP
	      "System Information Mode\n"
	      "Static user-specified\n"
	      "Dynamic, BSC-computed\n")
{
	struct gsm_bts *bts = vty->index;
	int type;

	type = get_string_value(osmo_sitype_strs, argv[0]);
	if (type < 0) {
		vty_out(vty, "%% Error SI Type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[1], "static"))
		bts->si_mode_static |= (1 << type);
	else
		bts->si_mode_static &= ~(1 << type);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_si_static,
	      cfg_bts_si_static_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "system-information " SI_TYPE_TEXT " static HEXSTRING",
	      SI_TEXT SI_TYPE_HELP
	      "Static System Information filling\n"
	      "Static user-specified SI content in HEX notation\n")
{
	struct gsm_bts *bts = vty->index;
	int rc, type;

	type = get_string_value(osmo_sitype_strs, argv[0]);
	if (type < 0) {
		vty_out(vty, "%% Error SI Type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!(bts->si_mode_static & (1 << type))) {
		vty_out(vty, "%% SI Type %s is not configured in static mode%s",
			get_value_string(osmo_sitype_strs, type), VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Fill buffer with padding pattern */
	memset(GSM_BTS_SI(bts, type), 0x2b, GSM_MACBLOCK_LEN);

	/* Parse the user-specified SI in hex format, [partially] overwriting padding */
	rc = osmo_hexparse(argv[1], GSM_BTS_SI(bts, type), GSM_MACBLOCK_LEN);
	if (rc < 0 || rc > GSM_MACBLOCK_LEN) {
		vty_out(vty, "%% Error parsing HEXSTRING%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Mark this SI as present */
	bts->si_valid |= (1 << type);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_si_unused_send_empty,
	      cfg_bts_si_unused_send_empty_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "system-information unused-send-empty",
	      SI_TEXT
	      "Send BCCH Info with empty 'Full BCCH Info' TLV to notify disabled SI. "
	      "Some nanoBTS fw versions are known to fail upon receival of these messages.\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_unused_send_empty = true;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_no_si_unused_send_empty,
	      cfg_bts_no_si_unused_send_empty_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "no system-information unused-send-empty",
	      NO_STR SI_TEXT
	      "Avoid sending BCCH Info with empty 'Full BCCH Info' TLV to notify disabled SI. "
	      "Some nanoBTS fw versions are known to fail upon receival of these messages.\n")
{
	struct gsm_bts *bts = vty->index;

	if (!is_ipaccess_bts(bts) || is_sysmobts_v2(bts)) {
		vty_out(vty, "%% This command is only intended for ipaccess nanoBTS. See OS#3707.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->si_unused_send_empty = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_early_cm,
	      cfg_bts_early_cm_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "early-classmark-sending (allowed|forbidden)",
	      "Early Classmark Sending\n"
	      "Early Classmark Sending is allowed\n"
	      "Early Classmark Sending is forbidden\n")
{
	struct gsm_bts *bts = vty->index;

	if (!strcmp(argv[0], "allowed"))
		bts->early_classmark_allowed = true;
	else
		bts->early_classmark_allowed = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_early_cm_3g,
	      cfg_bts_early_cm_3g_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "early-classmark-sending-3g (allowed|forbidden)",
	      "3G Early Classmark Sending\n"
	      "3G Early Classmark Sending is allowed\n"
	      "3G Early Classmark Sending is forbidden\n")
{
	struct gsm_bts *bts = vty->index;

	if (!strcmp(argv[0], "allowed"))
		bts->early_classmark_allowed_3g = true;
	else
		bts->early_classmark_allowed_3g = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_neigh_mode,
	      cfg_bts_neigh_mode_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "neighbor-list mode (automatic|manual|manual-si5)",
	      "Neighbor List\n" "Mode of Neighbor List generation\n"
	      "Automatically from all BTS in this BSC\n" "Manual\n"
	      "Manual with different lists for SI2 and SI5\n")
{
	struct gsm_bts *bts = vty->index;
	int mode = get_string_value(bts_neigh_mode_strs, argv[0]);

	switch (mode) {
	case NL_MODE_MANUAL_SI5SEP:
	case NL_MODE_MANUAL:
		/* make sure we clear the current list when switching to
		 * manual mode */
		if (bts->neigh_list_manual_mode == 0)
			memset(&bts->si_common.data.neigh_list, 0,
				sizeof(bts->si_common.data.neigh_list));
		break;
	default:
		break;
	}

	bts->neigh_list_manual_mode = mode;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_neigh,
	      cfg_bts_neigh_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "neighbor-list (add|del) arfcn <0-1023>",
	      "Neighbor List\n" "Add to manual neighbor list\n"
	      "Delete from manual neighbor list\n" "ARFCN of neighbor\n"
	      "ARFCN of neighbor\n")
{
	struct gsm_bts *bts = vty->index;
	struct bitvec *bv = &bts->si_common.neigh_list;
	uint16_t arfcn = atoi(argv[1]);
	enum gsm_band unused;

	if (bts->neigh_list_manual_mode == NL_MODE_AUTOMATIC) {
		vty_out(vty, "%% Cannot configure neighbor list in "
			"automatic mode%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (gsm_arfcn2band_rc(arfcn, &unused) < 0) {
		vty_out(vty, "%% Invalid arfcn %" PRIu16 " detected%s", arfcn, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "add"))
		bitvec_set_bit_pos(bv, arfcn, 1);
	else
		bitvec_set_bit_pos(bv, arfcn, 0);

	return CMD_SUCCESS;
}

/* help text should be kept in sync with EARFCN_*_INVALID defines */
DEFUN_USRATTR(cfg_bts_si2quater_neigh_add,
	      cfg_bts_si2quater_neigh_add_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "si2quater neighbor-list add earfcn <0-65535> thresh-hi <0-31> "
	      "thresh-lo <0-32> prio <0-8> qrxlv <0-32> meas <0-8>",
	      "SI2quater Neighbor List\n" "SI2quater Neighbor List\n"
	      "Add to manual SI2quater neighbor list\n"
	      "EARFCN of neighbor\n" "EARFCN of neighbor\n"
	      "threshold high bits\n" "threshold high bits\n"
	      "threshold low bits\n" "threshold low bits (32 means NA)\n"
	      "priority\n" "priority (8 means NA)\n"
	      "QRXLEVMIN\n" "QRXLEVMIN (32 means NA)\n"
	      "measurement bandwidth\n" "measurement bandwidth (8 means NA)\n")
{
	struct gsm_bts *bts = vty->index;
	struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
	uint16_t arfcn = atoi(argv[0]);
	uint8_t thresh_hi = atoi(argv[1]), thresh_lo = atoi(argv[2]),
		prio = atoi(argv[3]), qrx = atoi(argv[4]), meas = atoi(argv[5]);
	int r = bts_earfcn_add(bts, arfcn, thresh_hi, thresh_lo, prio, qrx, meas);

	switch (r) {
	case 1:
		vty_out(vty, "%% Warning: multiple threshold-high are not supported, overriding with %u%s",
			thresh_hi, VTY_NEWLINE);
		break;
	case EARFCN_THRESH_LOW_INVALID:
		vty_out(vty, "%% Warning: multiple threshold-low are not supported, overriding with %u%s",
			thresh_lo, VTY_NEWLINE);
		break;
	case EARFCN_QRXLV_INVALID + 1:
		vty_out(vty, "%% Warning: multiple QRXLEVMIN are not supported, overriding with %u%s",
			qrx, VTY_NEWLINE);
		break;
	case EARFCN_PRIO_INVALID:
		vty_out(vty, "%% Warning: multiple priorities are not supported, overriding with %u%s",
			prio, VTY_NEWLINE);
		break;
	default:
		if (r < 0) {
			vty_out(vty, "%% Unable to add ARFCN %u: %s%s", arfcn, strerror(-r), VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	if (si2q_num(bts) <= SI2Q_MAX_NUM)
		return CMD_SUCCESS;

	vty_out(vty, "%% Warning: not enough space in SI2quater (%u/%u used) for a given EARFCN %u%s",
		bts->si2q_count, SI2Q_MAX_NUM, arfcn, VTY_NEWLINE);
	osmo_earfcn_del(e, arfcn);

	return CMD_WARNING;
}

DEFUN_USRATTR(cfg_bts_si2quater_neigh_del,
	      cfg_bts_si2quater_neigh_del_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "si2quater neighbor-list del earfcn <0-65535>",
	      "SI2quater Neighbor List\n"
	      "SI2quater Neighbor List\n"
	      "Delete from SI2quater manual neighbor list\n"
	      "EARFCN of neighbor\n"
	      "EARFCN\n")
{
	struct gsm_bts *bts = vty->index;
	struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
	uint16_t arfcn = atoi(argv[0]);
	int r = osmo_earfcn_del(e, arfcn);
	if (r < 0) {
		vty_out(vty, "%% Unable to delete arfcn %u: %s%s", arfcn,
			strerror(-r), VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_si2quater_uarfcn_add,
	      cfg_bts_si2quater_uarfcn_add_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "si2quater neighbor-list add uarfcn <0-16383> <0-511> <0-1>",
	      "SI2quater Neighbor List\n"
	      "SI2quater Neighbor List\n" "Add to manual SI2quater neighbor list\n"
	      "UARFCN of neighbor\n" "UARFCN of neighbor\n" "scrambling code\n"
	      "diversity bit\n")
{
	struct gsm_bts *bts = vty->index;
	uint16_t arfcn = atoi(argv[0]), scramble = atoi(argv[1]);

	switch(bts_uarfcn_add(bts, arfcn, scramble, atoi(argv[2]))) {
	case -ENOMEM:
		vty_out(vty, "%% Unable to add UARFCN: max number of UARFCNs (%u) reached%s",
			MAX_EARFCN_LIST, VTY_NEWLINE);
		return CMD_WARNING;
	case -ENOSPC:
		vty_out(vty, "%% Warning: not enough space in SI2quater for a given UARFCN (%u, %u)%s",
			arfcn, scramble, VTY_NEWLINE);
		return CMD_WARNING;
	case -EADDRINUSE:
		vty_out(vty, "%% Unable to add UARFCN: (%u, %u) is already added%s",
			arfcn, scramble, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_si2quater_uarfcn_del,
	      cfg_bts_si2quater_uarfcn_del_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "si2quater neighbor-list del uarfcn <0-16383> <0-511>",
	      "SI2quater Neighbor List\n"
	      "SI2quater Neighbor List\n"
	      "Delete from SI2quater manual neighbor list\n"
	      "UARFCN of neighbor\n"
	      "UARFCN\n"
	      "scrambling code\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts_uarfcn_del(bts, atoi(argv[0]), atoi(argv[1])) < 0) {
		vty_out(vty, "%% Unable to delete uarfcn: pair not found%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_si5_neigh,
	      cfg_bts_si5_neigh_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "si5 neighbor-list (add|del) arfcn <0-1023>",
	      "SI5 Neighbor List\n"
	      "SI5 Neighbor List\n" "Add to manual SI5 neighbor list\n"
	      "Delete from SI5 manual neighbor list\n" "ARFCN of neighbor\n"
	      "ARFCN of neighbor\n")
{
	enum gsm_band unused;
	struct gsm_bts *bts = vty->index;
	struct bitvec *bv = &bts->si_common.si5_neigh_list;
	uint16_t arfcn = atoi(argv[1]);

	if (!bts->neigh_list_manual_mode) {
		vty_out(vty, "%% Cannot configure neighbor list in "
			"automatic mode%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (gsm_arfcn2band_rc(arfcn, &unused) < 0) {
		vty_out(vty, "%% Invalid arfcn %" PRIu16 " detected%s", arfcn, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "add"))
		bitvec_set_bit_pos(bv, arfcn, 1);
	else
		bitvec_set_bit_pos(bv, arfcn, 0);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_pcu_sock,
	   cfg_bts_pcu_sock_cmd,
	   "pcu-socket PATH",
	   "PCU Socket Path for using OsmoPCU co-located with BSC (legacy BTS)\n"
	   "Path in the file system for the unix-domain PCU socket\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	int rc;

	osmo_talloc_replace_string(bts, &bts->pcu_sock_path, argv[0]);
	pcu_sock_exit(bts);
	rc = pcu_sock_init(bts->pcu_sock_path, bts);
	if (rc < 0) {
		vty_out(vty, "%% Error creating PCU socket `%s' for BTS %u%s",
			bts->pcu_sock_path, bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_acc_rotate,
	   cfg_bts_acc_rotate_cmd,
	   "access-control-class-rotate <0-10>",
	   "Enable Access Control Class allowed subset rotation\n"
	   "Size of the rotating allowed ACC 0-9 subset (default=10, no subset)\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	int len_allowed_adm = atoi(argv[0]);
	acc_mgr_set_len_allowed_adm(&bts->acc_mgr, len_allowed_adm);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_acc_rotate_quantum,
	   cfg_bts_acc_rotate_quantum_cmd,
	   "access-control-class-rotate-quantum <1-65535>",
	   "Time between rotation of ACC 0-9 generated subsets\n"
	   "Time in seconds (default=" OSMO_STRINGIFY_VAL(ACC_MGR_QUANTUM_DEFAULT) ")\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	uint32_t rotation_time_sec = (uint32_t)atoi(argv[0]);
	acc_mgr_set_rotation_time(&bts->acc_mgr, rotation_time_sec);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_acc_ramping,
	   cfg_bts_acc_ramping_cmd,
	   "access-control-class-ramping",
	   "Enable Access Control Class ramping\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	struct gsm_bts_trx *trx;

	if (!acc_ramp_is_enabled(&bts->acc_ramp)) {
		acc_ramp_set_enabled(&bts->acc_ramp, true);
		/* Start ramping if at least one TRX is usable */
		llist_for_each_entry(trx, &bts->trx_list, list) {
			if (trx_is_usable(trx)) {
				acc_ramp_trigger(&bts->acc_ramp);
				break;
			}
		}
	}

	/*
	 * ACC ramping takes effect either when the BTS reconnects RSL,
	 * or when RF administrative state changes to 'unlocked'.
	 */
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_no_acc_ramping,
	   cfg_bts_no_acc_ramping_cmd,
	   "no access-control-class-ramping",
	   NO_STR
	   "Disable Access Control Class ramping\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;

	if (acc_ramp_is_enabled(&bts->acc_ramp)) {
		acc_ramp_abort(&bts->acc_ramp);
		acc_ramp_set_enabled(&bts->acc_ramp, false);
		if (gsm_bts_set_system_infos(bts) != 0) {
			vty_out(vty, "%% Filed to (re)generate System Information "
				"messages, check the logs%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_acc_ramping_step_interval,
	   cfg_bts_acc_ramping_step_interval_cmd,
	   "access-control-class-ramping-step-interval (<"
	   OSMO_STRINGIFY_VAL(ACC_RAMP_STEP_INTERVAL_MIN) "-"
	   OSMO_STRINGIFY_VAL(ACC_RAMP_STEP_INTERVAL_MAX) ">|dynamic)",
	   "Configure Access Control Class ramping step interval\n"
	   "Set a fixed step interval (in seconds)\n"
	   "Use dynamic step interval based on BTS channel load (deprecated, don't use, ignored)\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	bool dynamic = (strcmp(argv[0], "dynamic") == 0);
	int error;

	if (dynamic) {
		vty_out(vty, "%% access-control-class-ramping-step-interval 'dynamic' value is deprecated, ignoring it%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	error = acc_ramp_set_step_interval(&bts->acc_ramp, atoi(argv[0]));
	if (error != 0) {
		if (error == -ERANGE)
			vty_out(vty, "%% Unable to set ACC ramp step interval: value out of range%s", VTY_NEWLINE);
		else
			vty_out(vty, "%% Unable to set ACC ramp step interval: unknown error%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_acc_ramping_step_size,
	   cfg_bts_acc_ramping_step_size_cmd,
	   "access-control-class-ramping-step-size (<"
	   OSMO_STRINGIFY_VAL(ACC_RAMP_STEP_SIZE_MIN) "-"
	   OSMO_STRINGIFY_VAL(ACC_RAMP_STEP_SIZE_MAX) ">)",
	   "Configure Access Control Class ramping step size\n"
	   "Set the number of Access Control Classes to enable per ramping step\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	int error;

	error = acc_ramp_set_step_size(&bts->acc_ramp, atoi(argv[0]));
	if (error != 0) {
		if (error == -ERANGE)
			vty_out(vty, "%% Unable to set ACC ramp step size: value out of range%s", VTY_NEWLINE);
		else
			vty_out(vty, "%% Unable to set ACC ramp step size: unknown error%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_acc_ramping_chan_load,
	   cfg_bts_acc_ramping_chan_load_cmd,
	   "access-control-class-ramping-chan-load <0-100> <0-100>",
	   "Configure Access Control Class ramping channel load thresholds\n"
	   "Lower Channel load threshold (%) below which subset size of allowed broadcast ACCs can be increased\n"
	   "Upper channel load threshold (%) above which subset size of allowed broadcast ACCs can be decreased\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	int rc;

	rc = acc_ramp_set_chan_load_thresholds(&bts->acc_ramp, atoi(argv[0]), atoi(argv[1]));
	if (rc < 0) {
		vty_out(vty, "%% Unable to set ACC channel load thresholds%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

#define EXCL_RFLOCK_STR "Exclude this BTS from the global RF Lock\n"

DEFUN_ATTR(cfg_bts_excl_rf_lock,
	   cfg_bts_excl_rf_lock_cmd,
	   "rf-lock-exclude",
	   EXCL_RFLOCK_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	bts->excl_from_rf_lock = 1;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_no_excl_rf_lock,
	   cfg_bts_no_excl_rf_lock_cmd,
	   "no rf-lock-exclude",
	   NO_STR EXCL_RFLOCK_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	bts->excl_from_rf_lock = 0;
	return CMD_SUCCESS;
}

#define FORCE_COMB_SI_STR "Force the generation of a single SI (no ter/bis)\n"

DEFUN_USRATTR(cfg_bts_force_comb_si,
	      cfg_bts_force_comb_si_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "force-combined-si",
	      FORCE_COMB_SI_STR)
{
	struct gsm_bts *bts = vty->index;
	bts->force_combined_si = 1;
	bts->force_combined_si_set = true;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_no_force_comb_si,
	      cfg_bts_no_force_comb_si_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "no force-combined-si",
	      NO_STR FORCE_COMB_SI_STR)
{
	struct gsm_bts *bts = vty->index;
	bts->force_combined_si = 0;
	bts->force_combined_si_set = true;
	return CMD_SUCCESS;
}

static void _get_codec_from_arg(struct vty *vty, int argc, const char *argv[])
{
	struct gsm_bts *bts = vty->index;
	struct bts_codec_conf *codec = &bts->codec;
	int i;

	codec->hr = 0;
	codec->efr = 0;
	codec->amr = 0;
	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "hr"))
			codec->hr = 1;
		if (!strcmp(argv[i], "efr"))
			codec->efr = 1;
		if (!strcmp(argv[i], "amr"))
			codec->amr = 1;
	}
}

#define CODEC_PAR_STR	" (hr|efr|amr)"
#define CODEC_HELP_STR	"Half Rate\n" \
			"Enhanced Full Rate\nAdaptive Multirate\n"

DEFUN_USRATTR(cfg_bts_codec0,
	      cfg_bts_codec0_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "codec-support fr",
	      "Codec Support settings\nFullrate\n")
{
	_get_codec_from_arg(vty, 0, argv);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_codec1,
	      cfg_bts_codec1_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "codec-support fr" CODEC_PAR_STR,
	      "Codec Support settings\nFullrate\n"
	      CODEC_HELP_STR)
{
	_get_codec_from_arg(vty, 1, argv);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_codec2,
	      cfg_bts_codec2_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "codec-support fr" CODEC_PAR_STR CODEC_PAR_STR,
	      "Codec Support settings\nFullrate\n"
	      CODEC_HELP_STR CODEC_HELP_STR)
{
	_get_codec_from_arg(vty, 2, argv);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_codec3,
	      cfg_bts_codec3_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "codec-support fr" CODEC_PAR_STR CODEC_PAR_STR CODEC_PAR_STR,
	      "Codec Support settings\nFullrate\n"
	      CODEC_HELP_STR CODEC_HELP_STR CODEC_HELP_STR)
{
	_get_codec_from_arg(vty, 3, argv);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_codec4,
	      cfg_bts_codec4_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "codec-support fr" CODEC_PAR_STR CODEC_PAR_STR CODEC_PAR_STR CODEC_PAR_STR,
	      "Codec Support settings\nFullrate\n"
	      CODEC_HELP_STR CODEC_HELP_STR CODEC_HELP_STR CODEC_HELP_STR)
{
	_get_codec_from_arg(vty, 4, argv);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_depends_on, cfg_bts_depends_on_cmd,
	   "depends-on-bts <0-255>",
	   "This BTS can only be started if another one is up\n"
	   BTS_NR_STR, CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	struct gsm_bts *other_bts;
	int dep = atoi(argv[0]);


	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% This feature is only available for IP systems.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	other_bts = gsm_bts_num(bts->network, dep);
	if (!other_bts || !is_ipaccess_bts(other_bts)) {
		vty_out(vty, "%% This feature is only available for IP systems.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (dep >= bts->nr) {
		vty_out(vty, "%% Need to depend on an already declared unit.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts_depend_mark(bts, dep);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_no_depends_on, cfg_bts_no_depends_on_cmd,
	   "no depends-on-bts <0-255>",
	   NO_STR "This BTS can only be started if another one is up\n"
	   BTS_NR_STR, CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts *bts = vty->index;
	int dep = atoi(argv[0]);

	bts_depend_clear(bts, dep);
	return CMD_SUCCESS;
}

#define AMR_TEXT "Adaptive Multi Rate settings\n"
#define AMR_MODE_TEXT "Codec modes to use with AMR codec\n"
#define AMR_START_TEXT "Initial codec to use with AMR\n" \
	"Automatically\nFirst codec\nSecond codec\nThird codec\nFourth codec\n"
#define AMR_TH_TEXT "AMR threshold between codecs\nMS side\nBTS side\n"
#define AMR_HY_TEXT "AMR hysteresis between codecs\nMS side\nBTS side\n"

static int get_amr_from_arg(struct vty *vty, int argc, const char *argv[], int full)
{
	struct gsm_bts *bts = vty->index;
	struct amr_multirate_conf *mr = (full) ? &bts->mr_full: &bts->mr_half;
	struct gsm48_multi_rate_conf *mr_conf =
				(struct gsm48_multi_rate_conf *) mr->gsm48_ie;
	int i;
	int mode;
	int mode_prev = -1;

	/* Check if mode parameters are in order */
	for (i = 0; i < argc; i++) {
		mode = atoi(argv[i]);
		if (mode_prev > mode) {
			vty_out(vty, "%% Modes must be listed in order%s",
				VTY_NEWLINE);
			return -1;
		}

		if (mode_prev == mode) {
			vty_out(vty, "%% Modes must be unique %s", VTY_NEWLINE);
			return -2;
		}
		mode_prev = mode;
	}

	/* Prepare the multirate configuration IE */
	mr->gsm48_ie[1] = 0;
	for (i = 0; i < argc; i++)
		mr->gsm48_ie[1] |= 1 << atoi(argv[i]);
	mr_conf->icmi = 0;

	/* Store actual mode identifier values */
	for (i = 0; i < argc; i++) {
		mr->ms_mode[i].mode = atoi(argv[i]);
		mr->bts_mode[i].mode = atoi(argv[i]);
	}
	mr->num_modes = argc;

	/* Trim excess threshold and hysteresis values from previous config */
	for (i = argc - 1; i < 4; i++) {
		mr->ms_mode[i].threshold = 0;
		mr->bts_mode[i].threshold = 0;
		mr->ms_mode[i].hysteresis = 0;
		mr->bts_mode[i].hysteresis = 0;
	}
	return 0;
}

static void get_amr_th_from_arg(struct vty *vty, int argc, const char *argv[], int full)
{
	struct gsm_bts *bts = vty->index;
	struct amr_multirate_conf *mr = (full) ? &bts->mr_full: &bts->mr_half;
	struct amr_mode *modes;
	int i;

	modes = argv[0][0]=='m' ? mr->ms_mode : mr->bts_mode;
	for (i = 0; i < argc - 1; i++)
		modes[i].threshold = atoi(argv[i + 1]);
}

static void get_amr_hy_from_arg(struct vty *vty, int argc, const char *argv[], int full)
{
	struct gsm_bts *bts = vty->index;
	struct amr_multirate_conf *mr = (full) ? &bts->mr_full: &bts->mr_half;
	struct amr_mode *modes;
	int i;

	modes = argv[0][0]=='m' ? mr->ms_mode : mr->bts_mode;
	for (i = 0; i < argc - 1; i++)
		modes[i].hysteresis = atoi(argv[i + 1]);
}

static void get_amr_start_from_arg(struct vty *vty, const char *argv[], int full)
{
	struct gsm_bts *bts = vty->index;
	struct amr_multirate_conf *mr = (full) ? &bts->mr_full: &bts->mr_half;
	struct gsm48_multi_rate_conf *mr_conf =
				(struct gsm48_multi_rate_conf *) mr->gsm48_ie;
	int num = 0, i;

	for (i = 0; i < ((full) ? 8 : 6); i++) {
		if ((mr->gsm48_ie[1] & (1 << i))) {
			num++;
		}
	}

	if (argv[0][0] == 'a' || num == 0) {
		mr_conf->icmi = 0;
		mr_conf->smod = 0;
	} else {
		mr_conf->icmi = 1;
		if (num < atoi(argv[0]))
			mr_conf->smod = num - 1;
		else
			mr_conf->smod = atoi(argv[0]) - 1;
	}
}

/* Give the current amr configuration a final consistency check by feeding the
 * the configuration into the gsm48 multirate IE generator function */
static int check_amr_config(struct vty *vty)
{
	int rc = 0;
	struct amr_multirate_conf *mr;
	const struct gsm48_multi_rate_conf *mr_conf;
	struct gsm_bts *bts = vty->index;
	int vty_rc = CMD_SUCCESS;

	mr = &bts->mr_full;
	mr_conf = (struct gsm48_multi_rate_conf*) mr->gsm48_ie;
	rc = gsm48_multirate_config(NULL, mr_conf, mr->ms_mode, mr->num_modes);
	if (rc != 0) {
		vty_out(vty,
			"%% Invalid AMR multirate configuration (tch-f, ms) - check parameters%s",
			VTY_NEWLINE);
		vty_rc = CMD_WARNING;
	}

	rc = gsm48_multirate_config(NULL, mr_conf, mr->bts_mode, mr->num_modes);
	if (rc != 0) {
		vty_out(vty,
			"%% Invalid AMR multirate configuration (tch-f, bts) - check parameters%s",
			VTY_NEWLINE);
		vty_rc = CMD_WARNING;
	}

	mr = &bts->mr_half;
	mr_conf = (struct gsm48_multi_rate_conf*) mr->gsm48_ie;
	rc = gsm48_multirate_config(NULL, mr_conf, mr->ms_mode, mr->num_modes);
	if (rc != 0) {
		vty_out(vty,
			"%% Invalid AMR multirate configuration (tch-h, ms) - check parameters%s",
			VTY_NEWLINE);
		vty_rc = CMD_WARNING;
	}

	rc = gsm48_multirate_config(NULL, mr_conf, mr->bts_mode, mr->num_modes);
	if (rc != 0) {
		vty_out(vty,
			"%% Invalid AMR multirate configuration (tch-h, bts) - check parameters%s",
			VTY_NEWLINE);
		vty_rc = CMD_WARNING;
	}

	return vty_rc;
}

#define AMR_TCHF_PAR_STR " (0|1|2|3|4|5|6|7)"
#define AMR_TCHF_HELP_STR "4,75k\n5,15k\n5,90k\n6,70k\n7,40k\n7,95k\n" \
	"10,2k\n12,2k\n"

#define AMR_TCHH_PAR_STR " (0|1|2|3|4|5)"
#define AMR_TCHH_HELP_STR "4,75k\n5,15k\n5,90k\n6,70k\n7,40k\n7,95k\n"

#define	AMR_TH_HELP_STR "Threshold between codec 1 and 2\n"
#define	AMR_HY_HELP_STR "Hysteresis between codec 1 and 2\n"

DEFUN_USRATTR(cfg_bts_amr_fr_modes1,
	      cfg_bts_amr_fr_modes1_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f modes" AMR_TCHF_PAR_STR,
	      AMR_TEXT "Full Rate\n" AMR_MODE_TEXT
	      AMR_TCHF_HELP_STR)
{
	if (get_amr_from_arg(vty, 1, argv, 1))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_modes2,
	      cfg_bts_amr_fr_modes2_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f modes" AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR,
	      AMR_TEXT "Full Rate\n" AMR_MODE_TEXT
	      AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR)
{
	if (get_amr_from_arg(vty, 2, argv, 1))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_modes3,
	      cfg_bts_amr_fr_modes3_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f modes" AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR,
	      AMR_TEXT "Full Rate\n" AMR_MODE_TEXT
	      AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR)
{
	if (get_amr_from_arg(vty, 3, argv, 1))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_modes4,
	      cfg_bts_amr_fr_modes4_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f modes" AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR,
	      AMR_TEXT "Full Rate\n" AMR_MODE_TEXT
	      AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR)
{
	if (get_amr_from_arg(vty, 4, argv, 1))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_start_mode,
	      cfg_bts_amr_fr_start_mode_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f start-mode (auto|1|2|3|4)",
	      AMR_TEXT "Full Rate\n" AMR_START_TEXT)
{
	get_amr_start_from_arg(vty, argv, 1);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_thres1,
	      cfg_bts_amr_fr_thres1_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f threshold (ms|bts) <0-63>",
	      AMR_TEXT "Full Rate\n" AMR_TH_TEXT
	      AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 2, argv, 1);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_thres2,
	      cfg_bts_amr_fr_thres2_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f threshold (ms|bts) <0-63> <0-63>",
	      AMR_TEXT "Full Rate\n" AMR_TH_TEXT
	      AMR_TH_HELP_STR AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 3, argv, 1);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_thres3,
	      cfg_bts_amr_fr_thres3_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f threshold (ms|bts) <0-63> <0-63> <0-63>",
	      AMR_TEXT "Full Rate\n" AMR_TH_TEXT
	      AMR_TH_HELP_STR AMR_TH_HELP_STR AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 4, argv, 1);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_hyst1,
	      cfg_bts_amr_fr_hyst1_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f hysteresis (ms|bts) <0-15>",
	      AMR_TEXT "Full Rate\n" AMR_HY_TEXT
	      AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 2, argv, 1);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_fr_hyst2,
	      cfg_bts_amr_fr_hyst2_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f hysteresis (ms|bts) <0-15> <0-15>",
	      AMR_TEXT "Full Rate\n" AMR_HY_TEXT
	      AMR_HY_HELP_STR AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 3, argv, 1);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_bts_amr_fr_hyst3,
	      cfg_bts_amr_fr_hyst3_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-f hysteresis (ms|bts) <0-15> <0-15> <0-15>",
	      AMR_TEXT "Full Rate\n" AMR_HY_TEXT
	      AMR_HY_HELP_STR AMR_HY_HELP_STR AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 4, argv, 1);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_modes1,
	      cfg_bts_amr_hr_modes1_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h modes" AMR_TCHH_PAR_STR,
	      AMR_TEXT "Half Rate\n" AMR_MODE_TEXT
	      AMR_TCHH_HELP_STR)
{
	if (get_amr_from_arg(vty, 1, argv, 0))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_modes2,
	      cfg_bts_amr_hr_modes2_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h modes" AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR,
	      AMR_TEXT "Half Rate\n" AMR_MODE_TEXT
	      AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR)
{
	if (get_amr_from_arg(vty, 2, argv, 0))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_modes3,
	      cfg_bts_amr_hr_modes3_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h modes" AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR,
	      AMR_TEXT "Half Rate\n" AMR_MODE_TEXT
	      AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR)
{
	if (get_amr_from_arg(vty, 3, argv, 0))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_modes4,
	      cfg_bts_amr_hr_modes4_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h modes" AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR,
	      AMR_TEXT "Half Rate\n" AMR_MODE_TEXT
	      AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR)
{
	if (get_amr_from_arg(vty, 4, argv, 0))
		return CMD_WARNING;
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_start_mode,
	      cfg_bts_amr_hr_start_mode_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h start-mode (auto|1|2|3|4)",
	      AMR_TEXT "Half Rate\n" AMR_START_TEXT)
{
	get_amr_start_from_arg(vty, argv, 0);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_thres1,
	      cfg_bts_amr_hr_thres1_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h threshold (ms|bts) <0-63>",
	      AMR_TEXT "Half Rate\n" AMR_TH_TEXT
	      AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 2, argv, 0);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_thres2,
	      cfg_bts_amr_hr_thres2_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h threshold (ms|bts) <0-63> <0-63>",
	      AMR_TEXT "Half Rate\n" AMR_TH_TEXT
	      AMR_TH_HELP_STR AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 3, argv, 0);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_thres3,
	      cfg_bts_amr_hr_thres3_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h threshold (ms|bts) <0-63> <0-63> <0-63>",
	      AMR_TEXT "Half Rate\n" AMR_TH_TEXT
	      AMR_TH_HELP_STR AMR_TH_HELP_STR AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 4, argv, 0);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_hyst1,
	      cfg_bts_amr_hr_hyst1_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h hysteresis (ms|bts) <0-15>",
	      AMR_TEXT "Half Rate\n" AMR_HY_TEXT
	      AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 2, argv, 0);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_hyst2,
	      cfg_bts_amr_hr_hyst2_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h hysteresis (ms|bts) <0-15> <0-15>",
	      AMR_TEXT "Half Rate\n" AMR_HY_TEXT
	      AMR_HY_HELP_STR AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 3, argv, 0);
	return check_amr_config(vty);
}

DEFUN_USRATTR(cfg_bts_amr_hr_hyst3,
	      cfg_bts_amr_hr_hyst3_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr tch-h hysteresis (ms|bts) <0-15> <0-15> <0-15>",
	      AMR_TEXT "Half Rate\n" AMR_HY_TEXT
	      AMR_HY_HELP_STR AMR_HY_HELP_STR AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 4, argv, 0);
	return check_amr_config(vty);
}

#define TNUM_STR "T-number, optionally preceded by 't' or 'T'\n"
DEFUN_ATTR(cfg_bts_t3113_dynamic, cfg_bts_t3113_dynamic_cmd,
	   "timer-dynamic TNNNN",
	   "Calculate T3113 dynamically based on channel config and load\n"
	   TNUM_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_tdef *d;
	struct gsm_bts *bts = vty->index;
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	d = osmo_tdef_vty_parse_T_arg(vty, gsmnet->T_defs, argv[0]);
	if (!d)
		return CMD_WARNING;

	switch (d->T) {
	case 3113:
		bts->T3113_dynamic = true;
		break;
	default:
		vty_out(vty, "%% T%d cannot be set to dynamic%s", d->T, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_bts_no_t3113_dynamic, cfg_bts_no_t3113_dynamic_cmd,
	   "no timer-dynamic TNNNN",
	   NO_STR
	   "Set given timer to non-dynamic and use the default or user provided fixed value\n"
	   TNUM_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_tdef *d;
	struct gsm_bts *bts = vty->index;
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	d = osmo_tdef_vty_parse_T_arg(vty, gsmnet->T_defs, argv[0]);
	if (!d)
		return CMD_WARNING;

	switch (d->T) {
	case 3113:
		bts->T3113_dynamic = false;
		break;
	default:
		vty_out(vty, "%% T%d already is non-dynamic%s", d->T, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

#define BS_POWER_CONTROL_CMD \
	"bs-power-control"
#define MS_POWER_CONTROL_CMD \
	"ms-power-control"
#define POWER_CONTROL_CMD \
	"(" BS_POWER_CONTROL_CMD "|" MS_POWER_CONTROL_CMD ")"
#define POWER_CONTROL_DESC \
	"BS (Downlink) power control parameters\n" \
	"MS (Uplink) power control parameters\n"

#define BTS_POWER_CTRL_PARAMS(bts) \
	(strcmp(argv[0], BS_POWER_CONTROL_CMD) == 0) ? \
		&bts->bs_power_ctrl : &bts->ms_power_ctrl

DEFUN_USRATTR(cfg_bts_no_power_ctrl,
	      cfg_bts_no_power_ctrl_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "no " POWER_CONTROL_CMD,
	      NO_STR POWER_CONTROL_DESC)
{
	struct gsm_power_ctrl_params *params;
	struct gsm_bts *bts = vty->index;

	params = BTS_POWER_CTRL_PARAMS(bts);
	params->mode = GSM_PWR_CTRL_MODE_NONE;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_power_ctrl,
      cfg_bts_power_ctrl_cmd,
      POWER_CONTROL_CMD,
      POWER_CONTROL_DESC)
{
	struct gsm_power_ctrl_params *params;
	struct gsm_bts *bts = vty->index;

	params = BTS_POWER_CTRL_PARAMS(bts);
	vty->node = POWER_CTRL_NODE;
	vty->index = params;

	/* Change the prefix to reflect MS/BS difference */
	if (params->dir == GSM_PWR_CTRL_DIR_UL)
		power_ctrl_node.prompt = "%s(config-ms-power-ctrl)# ";
	else
		power_ctrl_node.prompt = "%s(config-bs-power-ctrl)# ";

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_mode,
	      cfg_power_ctrl_mode_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "mode (static|dyn-bts) [reset]",
	      "Power control mode\n"
	      "Instruct the MS/BTS to use a static power level\n"
	      "Power control to be performed dynamically by the BTS itself\n"
	      "Reset to default parameters for the given mode\n")
{
	struct gsm_power_ctrl_params *params = vty->index;

	/* Do we need to reset? */
	if (argc > 1) {
		vty_out(vty, "%% Reset to default parameters%s", VTY_NEWLINE);
		enum gsm_power_ctrl_dir dir = params->dir;
		*params = power_ctrl_params_def;
		params->dir = dir;
	}

	if (strcmp(argv[0], "static") == 0)
		params->mode = GSM_PWR_CTRL_MODE_STATIC;
	else if (strcmp(argv[0], "dyn-bts") == 0)
		params->mode = GSM_PWR_CTRL_MODE_DYN_BTS;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_bs_power,
	      cfg_power_ctrl_bs_power_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "bs-power (static|dyn-max) <0-30>",
	      "BS Power IE value to be send to the BTS\n"
	      "Fixed BS Power reduction value (for static mode)\n"
	      "Maximum BS Power reduction value (for dynamic mode)\n"
	      "BS Power reduction value (in dB, even numbers only)\n")
{
	struct gsm_power_ctrl_params *params = vty->index;
	bool dynamic = !strcmp(argv[0], "dyn-max");
	int value = atoi(argv[1]);

	if (params->dir != GSM_PWR_CTRL_DIR_DL) {
		vty_out(vty, "%% This command is only valid for "
			"'bs-power-control' node%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (value % 2 != 0) {
		vty_out(vty, "%% Incorrect BS Power reduction value, "
			"an even number is expected%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (dynamic) /* maximum value */
		params->bs_power_max_db = value;
	else /* static (fixed) value */
		params->bs_power_val_db = value;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_ctrl_interval,
	      cfg_power_ctrl_ctrl_interval_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "ctrl-interval <0-31>",
	      "Set power control interval (for dynamic mode)\n"
	      "P_CON_INTERVAL, in units of 2 SACCH periods (0.96 seconds)\n")
{
	struct gsm_power_ctrl_params *params = vty->index;

	params->ctrl_interval = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_step_size,
	      cfg_power_ctrl_step_size_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "step-size inc <2-6> red <2-4>",
	      "Set power change step size (for dynamic mode)\n"
	      "Increase step size (default is 4 dB)\n"
	      "Step size (2, 4, or 6 dB)\n"
	      "Reduce step size (default is 2 dB)\n"
	      "Step size (2 or 4 dB)\n")
{
	struct gsm_power_ctrl_params *params = vty->index;
	int inc_step_size_db = atoi(argv[0]);
	int red_step_size_db = atoi(argv[1]);

	if (inc_step_size_db % 2 || red_step_size_db % 2) {
		vty_out(vty, "%% Power change step size must be "
			"an even number%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Recommendation: POW_RED_STEP_SIZE <= POW_INCR_STEP_SIZE */
	if (red_step_size_db > inc_step_size_db) {
		vty_out(vty, "%% Increase step size (%d) should be greater "
			"than reduce step size (%d), consider changing it%s",
			inc_step_size_db, red_step_size_db, VTY_NEWLINE);
	}

	/* Recommendation: POW_INCR_STEP_SIZE <= (U_RXLEV_XX_P - L_RXLEV_XX_P) */
	const struct gsm_power_ctrl_meas_params *mp = &params->rxlev_meas;
	if (inc_step_size_db > (mp->upper_thresh - mp->lower_thresh)) {
		vty_out(vty, "%% Increase step size (%d) should be less or equal "
			"than/to the RxLev threshold window (%d, upper - lower), "
			"consider changing it%s", inc_step_size_db,
			mp->upper_thresh - mp->lower_thresh, VTY_NEWLINE);
	}

	params->inc_step_size_db = inc_step_size_db;
	params->red_step_size_db = red_step_size_db;

	return CMD_SUCCESS;
}

#define POWER_CONTROL_MEAS_RXLEV_DESC \
	"RxLev value (signal strength, 0 is worst, 63 is best)\n"
#define POWER_CONTROL_MEAS_RXQUAL_DESC \
	"RxQual value (signal quality, 0 is best, 7 is worst)\n"

DEFUN_USRATTR(cfg_power_ctrl_rxlev_thresh,
	      cfg_power_ctrl_rxlev_thresh_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "rxlev-thresh lower <0-63> upper <0-63>",
	      "Set target RxLev thresholds (for dynamic mode)\n"
	      "Lower RxLev value (default is 32, i.e. -78 dBm)\n"
	      "Lower " POWER_CONTROL_MEAS_RXLEV_DESC
	      "Upper RxLev value (default is 38, i.e. -72 dBm)\n"
	      "Upper " POWER_CONTROL_MEAS_RXLEV_DESC)
{
	struct gsm_power_ctrl_params *params = vty->index;
	int lower = atoi(argv[0]);
	int upper = atoi(argv[1]);

	if (lower > upper) {
		vty_out(vty, "%% Lower 'rxlev-thresh' (%d) must be less than upper (%d)%s",
			lower, upper, VTY_NEWLINE);
		return CMD_WARNING;
	}

	params->rxlev_meas.lower_thresh = lower;
	params->rxlev_meas.upper_thresh = upper;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_rxqual_thresh,
	      cfg_power_ctrl_rxqual_thresh_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "rxqual-thresh lower <0-7> upper <0-7>",
	      "Set target RxQual thresholds (for dynamic mode)\n"
	      "Lower RxQual value (default is 3, i.e. 0.8% <= BER < 1.6%)\n"
	      "Lower " POWER_CONTROL_MEAS_RXQUAL_DESC
	      "Upper RxQual value (default is 0, i.e. BER < 0.2%)\n"
	      "Upper " POWER_CONTROL_MEAS_RXQUAL_DESC)
{
	struct gsm_power_ctrl_params *params = vty->index;
	int lower = atoi(argv[0]);
	int upper = atoi(argv[1]);

	/* RxQual: 0 is best, 7 is worst, so upper must be less */
	if (upper > lower) {
		vty_out(vty, "%% Upper 'rxqual-rxqual' (%d) must be less than lower (%d)%s",
			upper, lower, VTY_NEWLINE);
		return CMD_WARNING;
	}

	params->rxqual_meas.lower_thresh = lower;
	params->rxqual_meas.upper_thresh = upper;

	return CMD_SUCCESS;
}

#define POWER_CONTROL_MEAS_THRESH_COMP_CMD(meas) \
	meas " lower <0-31> <0-31> upper <0-31> <0-31>"
#define POWER_CONTROL_MEAS_THRESH_COMP_DESC(meas, lp, ln, up, un) \
	"Set " meas " threshold comparators (for dynamic mode)\n" \
	"Lower " meas " threshold comparators (see 3GPP TS 45.008, A.3.2.1)\n" lp ln \
	"Upper " meas " threshold comparators (see 3GPP TS 45.008, A.3.2.1)\n" up un

DEFUN_USRATTR(cfg_power_ctrl_rxlev_thresh_comp,
	      cfg_power_ctrl_rxlev_thresh_comp_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      POWER_CONTROL_MEAS_THRESH_COMP_CMD("rxlev-thresh-comp"),
	      POWER_CONTROL_MEAS_THRESH_COMP_DESC("RxLev",
		"P1 (default 10)\n", "N1 (default 12)\n",
		"P2 (default 10)\n", "N2 (default 12)\n"))
{
	struct gsm_power_ctrl_params *params = vty->index;
	int lower_cmp_p = atoi(argv[0]);
	int lower_cmp_n = atoi(argv[1]);
	int upper_cmp_p = atoi(argv[2]);
	int upper_cmp_n = atoi(argv[3]);

	if (lower_cmp_p > lower_cmp_n) {
		vty_out(vty, "%% Lower RxLev P1 %d must be less than N1 %d%s",
			lower_cmp_p, lower_cmp_n, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (upper_cmp_p > upper_cmp_n) {
		vty_out(vty, "%% Upper RxLev P2 %d must be less than N2 %d%s",
			lower_cmp_p, lower_cmp_n, VTY_NEWLINE);
		return CMD_WARNING;
	}

	params->rxlev_meas.lower_cmp_p = lower_cmp_p;
	params->rxlev_meas.lower_cmp_n = lower_cmp_n;
	params->rxlev_meas.upper_cmp_p = upper_cmp_p;
	params->rxlev_meas.upper_cmp_n = upper_cmp_n;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_rxqual_thresh_comp,
	      cfg_power_ctrl_rxqual_thresh_comp_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      POWER_CONTROL_MEAS_THRESH_COMP_CMD("rxqual-thresh-comp"),
	      POWER_CONTROL_MEAS_THRESH_COMP_DESC("RxQual",
		"P3 (default 5)\n", "N3 (default 7)\n",
		"P4 (default 15)\n", "N4 (default 18)\n"))
{
	struct gsm_power_ctrl_params *params = vty->index;
	int lower_cmp_p = atoi(argv[0]);
	int lower_cmp_n = atoi(argv[1]);
	int upper_cmp_p = atoi(argv[2]);
	int upper_cmp_n = atoi(argv[3]);

	if (lower_cmp_p > lower_cmp_n) {
		vty_out(vty, "%% Lower RxQual P3 %d must be less than N3 %d%s",
			lower_cmp_p, lower_cmp_n, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (upper_cmp_p > upper_cmp_n) {
		vty_out(vty, "%% Upper RxQual P4 %d must be less than N4 %d%s",
			lower_cmp_p, lower_cmp_n, VTY_NEWLINE);
		return CMD_WARNING;
	}

	params->rxqual_meas.lower_cmp_p = lower_cmp_p;
	params->rxqual_meas.lower_cmp_n = lower_cmp_n;
	params->rxqual_meas.upper_cmp_p = upper_cmp_p;
	params->rxqual_meas.upper_cmp_n = upper_cmp_n;

	return CMD_SUCCESS;
}

#define POWER_CONTROL_MEAS_AVG_CMD \
	"(rxlev-avg|rxqual-avg)"
#define POWER_CONTROL_MEAS_AVG_DESC \
	"RxLev (signal strength) measurement averaging (for dynamic mode)\n" \
	"RxQual (signal quality) measurement averaging (for dynamic mode)\n"

#define POWER_CONTROL_MEAS_AVG_PARAMS(params) \
	(strncmp(argv[0], "rxlev", 5) == 0) ? \
		&params->rxlev_meas : &params->rxqual_meas

DEFUN_USRATTR(cfg_power_ctrl_no_avg,
	      cfg_power_ctrl_no_avg_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "no " POWER_CONTROL_MEAS_AVG_CMD,
	      NO_STR POWER_CONTROL_MEAS_AVG_DESC)
{
	struct gsm_power_ctrl_params *params = vty->index;
	struct gsm_power_ctrl_meas_params *avg_params;

	avg_params = POWER_CONTROL_MEAS_AVG_PARAMS(params);
	avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_NONE;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_avg_params,
	      cfg_power_ctrl_avg_params_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      POWER_CONTROL_MEAS_AVG_CMD " params hreqave <1-31> hreqt <1-31>",
	      POWER_CONTROL_MEAS_AVG_DESC "Configure general averaging parameters\n"
	      "Hreqave: the period over which an average is produced\n"
	      "Hreqave value (so that Hreqave * Hreqt < 32)\n"
	      "Hreqt: the number of averaged results that are maintained\n"
	      "Hreqt value (so that Hreqave * Hreqt < 32)\n")
{
	struct gsm_power_ctrl_params *params = vty->index;
	struct gsm_power_ctrl_meas_params *avg_params;
	int h_reqave = atoi(argv[1]);
	int h_reqt = atoi(argv[2]);

	if (h_reqave * h_reqt > 31) {
		vty_out(vty, "%% Hreqave (%d) * Hreqt (%d) = %d must be < 32%s",
			h_reqave, h_reqt, h_reqave * h_reqt, VTY_NEWLINE);
		return CMD_WARNING;
	}

	avg_params = POWER_CONTROL_MEAS_AVG_PARAMS(params);
	avg_params->h_reqave = h_reqave;
	avg_params->h_reqt = h_reqt;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_avg_algo,
	      cfg_power_ctrl_avg_algo_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      /* FIXME: add algorithm specific parameters */
	      POWER_CONTROL_MEAS_AVG_CMD " algo (unweighted|weighted|mod-median)",
	      POWER_CONTROL_MEAS_AVG_DESC "Select the averaging algorithm\n"
	      "Un-weighted average\n" "Weighted average\n"
	      "Modified median calculation\n")
{
	struct gsm_power_ctrl_params *params = vty->index;
	struct gsm_power_ctrl_meas_params *avg_params;

	avg_params = POWER_CONTROL_MEAS_AVG_PARAMS(params);
	if (strcmp(argv[1], "unweighted") == 0)
		avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_UNWEIGHTED;
	else if (strcmp(argv[1], "weighted") == 0)
		avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_WEIGHTED;
	else if (strcmp(argv[1], "mod-median") == 0)
		avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_MOD_MEDIAN;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_power_ctrl_avg_osmo_ewma,
	      cfg_power_ctrl_avg_osmo_ewma_cmd,
	      X(BSC_VTY_ATTR_VENDOR_SPECIFIC) |
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      POWER_CONTROL_MEAS_AVG_CMD " algo osmo-ewma beta <1-99>",
	      POWER_CONTROL_MEAS_AVG_DESC "Select the averaging algorithm\n"
	      "Exponentially Weighted Moving Average (EWMA)\n"
	      "Smoothing factor (in %): beta = (100 - alpha)\n"
	      "1% - lowest smoothing, 99% - highest smoothing\n")
{
	struct gsm_power_ctrl_params *params = vty->index;
	struct gsm_power_ctrl_meas_params *avg_params;
	const struct gsm_bts *bts;

	if (params->dir == GSM_PWR_CTRL_DIR_UL)
		bts = container_of(params, struct gsm_bts, ms_power_ctrl);
	else
		bts = container_of(params, struct gsm_bts, bs_power_ctrl);

	if (bts->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% EWMA is an OsmoBTS specific algorithm, "
			"it's not usable for other BTS types%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	avg_params = POWER_CONTROL_MEAS_AVG_PARAMS(params);
	avg_params->algo = GSM_PWR_CTRL_MEAS_AVG_ALGO_OSMO_EWMA;
	avg_params->ewma.alpha = 100 - atoi(argv[1]);

	return CMD_SUCCESS;
}

#define TRX_TEXT "Radio Transceiver\n"

/* per TRX configuration */
DEFUN_ATTR(cfg_trx,
	   cfg_trx_cmd,
	   "trx <0-255>",
	   TRX_TEXT
	   "Select a TRX to configure\n",
	   CMD_ATTR_IMMEDIATE)
{
	int trx_nr = atoi(argv[0]);
	struct gsm_bts *bts = vty->index;
	struct gsm_bts_trx *trx;

	if (trx_nr > bts->num_trx) {
		vty_out(vty, "%% The next unused TRX number in this BTS is %u%s",
			bts->num_trx, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (trx_nr == bts->num_trx) {
		/* we need to allocate a new one */
		trx = gsm_bts_trx_alloc(bts);
	} else
		trx = gsm_bts_trx_num(bts, trx_nr);

	if (!trx)
		return CMD_WARNING;

	vty->index = trx;
	vty->index_sub = &trx->description;
	vty->node = TRX_NODE;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trx_arfcn,
	      cfg_trx_arfcn_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "arfcn <0-1023>",
	      "Set the ARFCN for this TRX\n"
	      "Absolute Radio Frequency Channel Number\n")
{
	enum gsm_band unused;
	struct gsm_bts_trx *trx = vty->index;
	int arfcn = atoi(argv[0]);

	if (gsm_arfcn2band_rc(arfcn, &unused) < 0) {
		vty_out(vty, "%% Invalid arfcn %" PRIu16 " detected%s", arfcn, VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* FIXME: check if this ARFCN is supported by this TRX */

	trx->arfcn = arfcn;

	/* FIXME: patch ARFCN into SYSTEM INFORMATION */
	/* FIXME: use OML layer to update the ARFCN */
	/* FIXME: use RSL layer to update SYSTEM INFORMATION */

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trx_nominal_power,
	      cfg_trx_nominal_power_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "nominal power <-20-100>",
	      "Nominal TRX RF Power in dBm\n"
	      "Nominal TRX RF Power in dBm\n"
	      "Nominal TRX RF Power in dBm\n")
{
	struct gsm_bts_trx *trx = vty->index;

	trx->nominal_power = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trx_max_power_red,
	      cfg_trx_max_power_red_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "max_power_red <0-100>",
	      "Reduction of maximum BS RF Power (relative to nominal power)\n"
	      "Reduction of maximum BS RF Power in dB\n")
{
	int maxpwr_r = atoi(argv[0]);
	struct gsm_bts_trx *trx = vty->index;
	int upper_limit = 24;	/* default 12.21 max power red. */

	/* FIXME: check if our BTS type supports more than 12 */
	if (maxpwr_r < 0 || maxpwr_r > upper_limit) {
		vty_out(vty, "%% Power %d dB is not in the valid range%s",
			maxpwr_r, VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (maxpwr_r & 1) {
		vty_out(vty, "%% Power %d dB is not an even value%s",
			maxpwr_r, VTY_NEWLINE);
		return CMD_WARNING;
	}

	trx->max_power_red = maxpwr_r;

	/* FIXME: make sure we update this using OML */

	return CMD_SUCCESS;
}

/* NOTE: This requires a full restart as bsc_network_configure() is executed
 * only once on startup from osmo_bsc_main.c */
DEFUN(cfg_trx_rsl_e1,
      cfg_trx_rsl_e1_cmd,
      "rsl e1 line E1_LINE timeslot <1-31> sub-slot (0|1|2|3|full)",
      "RSL Parameters\n"
      "E1/T1 interface to be used for RSL\n"
      "E1/T1 interface to be used for RSL\n"
      "E1/T1 Line Number to be used for RSL\n"
      "E1/T1 Timeslot to be used for RSL\n"
      "E1/T1 Timeslot to be used for RSL\n"
      "E1/T1 Sub-slot to be used for RSL\n"
      "E1/T1 Sub-slot 0 is to be used for RSL\n"
      "E1/T1 Sub-slot 1 is to be used for RSL\n"
      "E1/T1 Sub-slot 2 is to be used for RSL\n"
      "E1/T1 Sub-slot 3 is to be used for RSL\n"
      "E1/T1 full timeslot is to be used for RSL\n")
{
	struct gsm_bts_trx *trx = vty->index;

	parse_e1_link(&trx->rsl_e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_trx_rsl_e1_tei,
	      cfg_trx_rsl_e1_tei_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "rsl e1 tei <0-63>",
	      "RSL Parameters\n"
	      "Set the TEI to be used for RSL\n"
	      "Set the TEI to be used for RSL\n"
	      "TEI to be used for RSL\n")
{
	struct gsm_bts_trx *trx = vty->index;

	trx->rsl_tei = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_trx_rf_locked,
	   cfg_trx_rf_locked_cmd,
	   "rf_locked (0|1)",
	   "Set or unset the RF Locking (Turn off RF of the TRX)\n"
	   "TRX is NOT RF locked (active)\n"
	   "TRX is RF locked (turned off)\n",
	   CMD_ATTR_IMMEDIATE)
{
	int locked = atoi(argv[0]);
	struct gsm_bts_trx *trx = vty->index;

	gsm_trx_lock_rf(trx, locked, "vty");
	return CMD_SUCCESS;
}

/* per TS configuration */
DEFUN_ATTR(cfg_ts,
	   cfg_ts_cmd,
	   "timeslot <0-7>",
	   "Select a Timeslot to configure\n"
	   "Timeslot number\n",
	   CMD_ATTR_IMMEDIATE)
{
	int ts_nr = atoi(argv[0]);
	struct gsm_bts_trx *trx = vty->index;
	struct gsm_bts_trx_ts *ts;

	if (ts_nr >= TRX_NR_TS) {
		vty_out(vty, "%% A GSM TRX only has %u Timeslots per TRX%s",
			TRX_NR_TS, VTY_NEWLINE);
		return CMD_WARNING;
	}

	ts = &trx->ts[ts_nr];

	vty->index = ts;
	vty->node = TS_NODE;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_ts_pchan,
	      cfg_ts_pchan_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "phys_chan_config PCHAN", /* dynamically generated! */
	      "Physical Channel configuration (TCH/SDCCH/...)\n" "Physical Channel\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int pchanc;

	pchanc = gsm_pchan_parse(argv[0]);
	if (pchanc < 0)
		return CMD_WARNING;

	ts->pchan_from_config = pchanc;

	return CMD_SUCCESS;
}

/* used for backwards compatibility with old config files that still
 * have uppercase pchan type names */
DEFUN_HIDDEN(cfg_ts_pchan_compat,
      cfg_ts_pchan_compat_cmd,
      "phys_chan_config PCHAN",
      "Physical Channel configuration (TCH/SDCCH/...)\n" "Physical Channel\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int pchanc;

	pchanc = gsm_pchan_parse(argv[0]);
	if (pchanc < 0) {
		vty_out(vty, "Unknown physical channel name '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_ERR_NO_MATCH;
	}

	ts->pchan_from_config = pchanc;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_ts_tsc,
	      cfg_ts_tsc_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "training_sequence_code <0-7>",
	      "Training Sequence Code of the Timeslot\n" "TSC\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	if (!osmo_bts_has_feature(&ts->trx->bts->model->features, BTS_FEAT_MULTI_TSC)) {
		vty_out(vty, "%% This BTS does not support a TSC != BCC, "
			"falling back to BCC%s", VTY_NEWLINE);
		ts->tsc = -1;
		return CMD_WARNING;
	}

	ts->tsc = atoi(argv[0]);

	return CMD_SUCCESS;
}

#define HOPPING_STR "Configure frequency hopping\n"

DEFUN_USRATTR(cfg_ts_hopping,
	      cfg_ts_hopping_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "hopping enabled (0|1)",
	      HOPPING_STR "Enable or disable frequency hopping\n"
	      "Disable frequency hopping\n" "Enable frequency hopping\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int enabled = atoi(argv[0]);

	if (enabled && !osmo_bts_has_feature(&ts->trx->bts->model->features, BTS_FEAT_HOPPING)) {
		vty_out(vty, "%% BTS model does not seem to support freq. hopping%s", VTY_NEWLINE);
		/* Allow enabling frequency hopping anyway, because the BTS might not have
		 * connected yet (thus not sent the feature vector), so we cannot know for
		 * sure.  Jet print a warning and let it go. */
	}

	ts->hopping.enabled = enabled;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_ts_hsn,
	      cfg_ts_hsn_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "hopping sequence-number <0-63>",
	      HOPPING_STR
	      "Which hopping sequence to use for this channel\n"
	      "Hopping Sequence Number (HSN)\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	ts->hopping.hsn = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_ts_maio,
	      cfg_ts_maio_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "hopping maio <0-63>",
	      HOPPING_STR
	      "Which hopping MAIO to use for this channel\n"
	      "Mobile Allocation Index Offset (MAIO)\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	ts->hopping.maio = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_ts_arfcn_add,
	      cfg_ts_arfcn_add_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "hopping arfcn add <0-1023>",
	      HOPPING_STR "Configure hopping ARFCN list\n"
	      "Add an entry to the hopping ARFCN list\n" "ARFCN\n")
{
	enum gsm_band unused;
	struct gsm_bts_trx_ts *ts = vty->index;
	int arfcn = atoi(argv[0]);

	if (gsm_arfcn2band_rc(arfcn, &unused) < 0) {
		vty_out(vty, "%% Invalid arfcn %" PRIu16 " detected%s", arfcn, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bitvec_set_bit_pos(&ts->hopping.arfcns, arfcn, 1);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_ts_arfcn_del,
	      cfg_ts_arfcn_del_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "hopping arfcn del <0-1023>",
	      HOPPING_STR "Configure hopping ARFCN list\n"
	      "Delete an entry to the hopping ARFCN list\n" "ARFCN\n")
{
	enum gsm_band unused;
	struct gsm_bts_trx_ts *ts = vty->index;
	int arfcn = atoi(argv[0]);

	if (gsm_arfcn2band_rc(arfcn, &unused) < 0) {
		vty_out(vty, "%% Invalid arfcn %" PRIu16 " detected%s", arfcn, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bitvec_set_bit_pos(&ts->hopping.arfcns, arfcn, 0);

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_ts_arfcn_del_all,
	      cfg_ts_arfcn_del_all_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_OML_LINK),
	      "hopping arfcn del-all",
	      HOPPING_STR "Configure hopping ARFCN list\n"
	      "Delete all previously configured entries\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	bitvec_zero(&ts->hopping.arfcns);

	return CMD_SUCCESS;
}

/* NOTE: This will have an effect on newly created voice lchans since the E1
 * voice channels are handled by osmo-mgw and the information put in e1_link
 * here is only used to generate the MGCP messages for the mgw. */
DEFUN_ATTR(cfg_ts_e1_subslot,
	   cfg_ts_e1_subslot_cmd,
	   "e1 line E1_LINE timeslot <1-31> sub-slot (0|1|2|3|full)",
	   "E1/T1 channel connected to this on-air timeslot\n"
	   "E1/T1 channel connected to this on-air timeslot\n"
	   "E1/T1 line connected to this on-air timeslot\n"
	   "E1/T1 timeslot connected to this on-air timeslot\n"
	   "E1/T1 timeslot connected to this on-air timeslot\n"
	   "E1/T1 sub-slot connected to this on-air timeslot\n"
	   "E1/T1 sub-slot 0 connected to this on-air timeslot\n"
	   "E1/T1 sub-slot 1 connected to this on-air timeslot\n"
	   "E1/T1 sub-slot 2 connected to this on-air timeslot\n"
	   "E1/T1 sub-slot 3 connected to this on-air timeslot\n"
	   "Full E1/T1 timeslot connected to this on-air timeslot\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_bts_trx_ts *ts = vty->index;

	parse_e1_link(&ts->e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}

int print_counter(struct rate_ctr_group *bsc_ctrs, struct rate_ctr *ctr, const struct rate_ctr_desc *desc, void *data)
{
	struct vty *vty = data;
	vty_out(vty, "%25s: %10"PRIu64" %s%s", desc->name, ctr->current, desc->description, VTY_NEWLINE);
	return 0;
}

void openbsc_vty_print_statistics(struct vty *vty, struct gsm_network *net)
{
	rate_ctr_for_each_counter(net->bsc_ctrs, print_counter, vty);
}

DEFUN(drop_bts,
      drop_bts_cmd,
      "drop bts connection <0-65535> (oml|rsl)",
      "Debug/Simulation command to drop Abis/IP BTS\n"
      "Debug/Simulation command to drop Abis/IP BTS\n"
      "Debug/Simulation command to drop Abis/IP BTS\n"
      "BTS NR\n" "Drop OML Connection\n" "Drop RSL Connection\n")
{
	struct gsm_network *gsmnet;
	struct gsm_bts_trx *trx;
	struct gsm_bts *bts;
	unsigned int bts_nr;

	gsmnet = gsmnet_from_vty(vty);

	bts_nr = atoi(argv[0]);
	if (bts_nr >= gsmnet->num_bts) {
		vty_out(vty, "%% BTS number must be between 0 and %d. It was %d.%s",
			gsmnet->num_bts, bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(gsmnet, bts_nr);
	if (!bts) {
		vty_out(vty, "%% BTS Nr. %d could not be found.%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% This command only works for ipaccess.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}


	/* close all connections */
	if (strcmp(argv[1], "oml") == 0) {
		ipaccess_drop_oml(bts, "vty");
	} else if (strcmp(argv[1], "rsl") == 0) {
		/* close all rsl connections */
		llist_for_each_entry(trx, &bts->trx_list, list) {
			ipaccess_drop_rsl(trx, "vty");
		}
	} else {
		vty_out(vty, "%% Argument must be 'oml' or 'rsl'.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(restart_bts, restart_bts_cmd,
      "restart-bts <0-65535>",
      "Restart ip.access nanoBTS through OML\n"
      BTS_NR_STR)
{
	struct gsm_network *gsmnet;
	struct gsm_bts_trx *trx;
	struct gsm_bts *bts;
	unsigned int bts_nr;

	gsmnet = gsmnet_from_vty(vty);

	bts_nr = atoi(argv[0]);
	if (bts_nr >= gsmnet->num_bts) {
		vty_out(vty, "%% BTS number must be between 0 and %d. It was %d.%s",
			gsmnet->num_bts, bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(gsmnet, bts_nr);
	if (!bts) {
		vty_out(vty, "%% BTS Nr. %d could not be found.%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!is_ipaccess_bts(bts) || is_sysmobts_v2(bts)) {
		vty_out(vty, "%% This command only works for ipaccess nanoBTS.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* go from last TRX to c0 */
	llist_for_each_entry_reverse(trx, &bts->trx_list, list)
		abis_nm_ipaccess_restart(trx);

	return CMD_SUCCESS;
}

DEFUN(bts_resend_sysinfo,
      bts_resend_sysinfo_cmd,
      "bts <0-255> resend-system-information",
      "BTS Specific Commands\n" BTS_NR_STR
      "Re-generate + re-send BCCH SYSTEM INFORMATION\n")
{
	struct gsm_network *gsmnet;
	struct gsm_bts *bts;
	unsigned int bts_nr;

	gsmnet = gsmnet_from_vty(vty);

	bts_nr = atoi(argv[0]);
	if (bts_nr >= gsmnet->num_bts) {
		vty_out(vty, "%% BTS number must be between 0 and %d. It was %d.%s",
			gsmnet->num_bts, bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(gsmnet, bts_nr);
	if (!bts) {
		vty_out(vty, "%% BTS Nr. %d could not be found.%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (gsm_bts_set_system_infos(bts) != 0) {
		vty_out(vty, "%% Filed to (re)generate System Information "
			"messages, check the logs%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(bts_resend_power_ctrl_params,
      bts_resend_power_ctrl_params_cmd,
      "bts <0-255> resend-power-control-defaults",
      "BTS Specific Commands\n" BTS_NR_STR
      "Re-generate + re-send default MS/BS Power control parameters\n")
{
	const struct gsm_bts_trx *trx;
	const struct gsm_bts *bts;
	int bts_nr = atoi(argv[0]);

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (bts->model->power_ctrl_send_def_params == NULL) {
		vty_out(vty, "%% Sending default MS/BS Power control parameters "
			"for BTS%d is not implemented%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	llist_for_each_entry(trx, &bts->trx_list, list) {
		if (bts->model->power_ctrl_send_def_params(trx) != 0) {
			vty_out(vty, "%% Failed to send default MS/BS Power control parameters "
				"to BTS%d/TRX%d%s", bts_nr, trx->nr, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

/* this command is now hidden, as it's a low-level debug hack, and people should
 * instead use osmo-cbc these days */
DEFUN_HIDDEN(smscb_cmd, smscb_cmd_cmd,
	"bts <0-255> smscb-command (normal|schedule|default) <1-4> HEXSTRING",
	"BTS related commands\n" BTS_NR_STR
	"SMS Cell Broadcast\n"
	"Normal (one-shot) SMSCB Message; sent once over Abis+Um\n"
	"Schedule (one-shot) SMSCB Message; sent once over Abis+Um\n"
	"Default (repeating) SMSCB Message; sent once over Abis, unlimited ovrer Um\n"
	"Last Valid Block\n"
	"Hex Encoded SMSCB message (up to 88 octets)\n")
{
	struct gsm_bts *bts;
	int bts_nr = atoi(argv[0]);
	const char *type_str = argv[1];
	int last_block = atoi(argv[2]);
	struct rsl_ie_cb_cmd_type cb_cmd;
	uint8_t buf[88];
	int rc;

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (!gsm_bts_get_cbch(bts)) {
		vty_out(vty, "%% BTS %d doesn't have a CBCH%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}
	rc = osmo_hexparse(argv[3], buf, sizeof(buf));
	if (rc < 0 || rc > sizeof(buf)) {
		vty_out(vty, "%% Error parsing HEXSTRING%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	cb_cmd.spare = 0;
	cb_cmd.def_bcast = 0;
	if (!strcmp(type_str, "normal"))
		cb_cmd.command = RSL_CB_CMD_TYPE_NORMAL;
	else if (!strcmp(type_str, "schedule"))
		cb_cmd.command = RSL_CB_CMD_TYPE_SCHEDULE;
	else if (!strcmp(type_str, "default"))
		cb_cmd.command = RSL_CB_CMD_TYPE_DEFAULT;
	else {
		vty_out(vty, "%% Error parsing type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	switch (last_block) {
	case 1:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_1;
		break;
	case 2:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_2;
		break;
	case 3:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_3;
		break;
	case 4:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_4;
		break;
	default:
		vty_out(vty, "%% Error parsing LASTBLOCK%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* SDCCH4 might not be correct here if the CBCH is on a SDCCH8? */
	rsl_sms_cb_command(bts, RSL_CHAN_SDCCH4_ACCH, cb_cmd, false, buf, rc);

	return CMD_SUCCESS;
}

/* resolve a gsm_bts_trx_ts basd on the given numeric identifiers */
static struct gsm_bts_trx_ts *vty_get_ts(struct vty *vty, const char *bts_str, const char *trx_str,
					 const char *ts_str)
{
	int bts_nr = atoi(bts_str);
	int trx_nr = atoi(trx_str);
	int ts_nr = atoi(ts_str);
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return NULL;
	}

	trx = gsm_bts_trx_num(bts, trx_nr);
	if (!trx) {
		vty_out(vty, "%% No such TRX (%d)%s", trx_nr, VTY_NEWLINE);
		return NULL;
	}

	ts = &trx->ts[ts_nr];

	return ts;
}

DEFUN(pdch_act, pdch_act_cmd,
	"bts <0-255> trx <0-255> timeslot <0-7> pdch (activate|deactivate)",
	BTS_NR_TRX_TS_STR2
	"Packet Data Channel\n"
	"Activate Dynamic PDCH/TCH (-> PDCH mode)\n"
	"Deactivate Dynamic PDCH/TCH (-> TCH mode)\n")
{
	struct gsm_bts_trx_ts *ts;
	int activate;

	ts = vty_get_ts(vty, argv[0], argv[1], argv[2]);
	if (!ts || !ts->fi || ts->fi->state == TS_ST_NOT_INITIALIZED || ts->fi->state == TS_ST_BORKEN) {
		vty_out(vty, "%% Timeslot is not usable%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!is_ipaccess_bts(ts->trx->bts)) {
		vty_out(vty, "%% This command only works for ipaccess BTS%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (ts->pchan_on_init != GSM_PCHAN_TCH_F_TCH_H_PDCH
	    && ts->pchan_on_init != GSM_PCHAN_TCH_F_PDCH) {
		vty_out(vty, "%% Timeslot %u is not dynamic TCH/F_TCH/H_PDCH or TCH/F_PDCH%s",
			ts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[3], "activate"))
		activate = 1;
	else
		activate = 0;

	if (activate && ts->fi->state != TS_ST_UNUSED) {
		vty_out(vty, "%% Timeslot %u is still in use%s",
			ts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (!activate && ts->fi->state != TS_ST_PDCH) {
		vty_out(vty, "%% Timeslot %u is not in PDCH mode%s",
			ts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	LOG_TS(ts, LOGL_NOTICE, "telnet VTY user asks to %s\n", activate ? "PDCH ACT" : "PDCH DEACT");
	ts->pdch_act_allowed = activate;
	osmo_fsm_inst_state_chg(ts->fi, activate ? TS_ST_WAIT_PDCH_ACT : TS_ST_WAIT_PDCH_DEACT, 4, 0);

	return CMD_SUCCESS;

}


/* Activate / Deactivate a single lchan with a specific codec mode */
static int lchan_act_single(struct vty *vty, struct gsm_lchan *lchan, const char *codec_str, int amr_mode, int activate)
{
	struct lchan_activate_info info = { };
	uint16_t amr_modes[8] =
	    { GSM0808_SC_CFG_AMR_4_75, GSM0808_SC_CFG_AMR_4_75_5_90_7_40_12_20, GSM0808_SC_CFG_AMR_5_90,
	      GSM0808_SC_CFG_AMR_6_70, GSM0808_SC_CFG_AMR_7_40, GSM0808_SC_CFG_AMR_7_95, GSM0808_SC_CFG_AMR_10_2,
	      GSM0808_SC_CFG_AMR_12_2 };

	if (activate) {
		LOG_LCHAN(lchan, LOGL_NOTICE, "attempt from VTY to activate lchan %s with codec %s\n",
			  gsm_lchan_name(lchan), codec_str);

		int lchan_t;
		if (lchan->fi->state != LCHAN_ST_UNUSED) {
			vty_out(vty, "%% Cannot activate: Channel busy!%s", VTY_NEWLINE);
			return CMD_WARNING;
		}

		/* pick a suitable lchan type */
		lchan_t = gsm_lchan_type_by_pchan(lchan->ts->pchan_is);
		if (lchan_t < 0) {
			if (lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_PDCH && !strcmp(codec_str, "fr"))
				lchan_t = GSM_LCHAN_TCH_F;
			else if (lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_TCH_H_PDCH && !strcmp(codec_str, "hr"))
				lchan_t = GSM_LCHAN_TCH_H;
			else if ((lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_PDCH
				  || lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_TCH_H_PDCH)
				 && !strcmp(codec_str, "fr"))
				lchan_t = GSM_LCHAN_TCH_F;
			else {
				vty_out(vty, "%% Cannot activate: Invalid lchan type (%s)!%s",
					gsm_pchan_name(lchan->ts->pchan_on_init), VTY_NEWLINE);
				return CMD_WARNING;
			}
		}

		/* configure the lchan */
		lchan->type = lchan_t;
		if (!strcmp(codec_str, "hr") || !strcmp(codec_str, "fr")) {
			info = (struct lchan_activate_info) {
				.activ_for = FOR_VTY,
				.chan_mode = GSM48_CMODE_SPEECH_V1,
				.requires_voice_stream = false,
			};
		} else if (!strcmp(codec_str, "efr")) {
			info = (struct lchan_activate_info) {
				.activ_for = FOR_VTY,
				.chan_mode = GSM48_CMODE_SPEECH_EFR,
				.s15_s0 = amr_modes[amr_mode],
				.requires_voice_stream = false,
			};
		} else if (!strcmp(codec_str, "amr")) {
			if (amr_mode == -1) {
				vty_out(vty, "%% AMR requires specification of AMR mode%s", VTY_NEWLINE);
				return CMD_WARNING;
			}
			info = (struct lchan_activate_info) {
				.activ_for = FOR_VTY,
				.chan_mode = GSM48_CMODE_SPEECH_AMR,
				.s15_s0 = amr_modes[amr_mode],
				.requires_voice_stream = false,
			};
		} else if (!strcmp(codec_str, "sig")) {
			info = (struct lchan_activate_info) {
				.activ_for = FOR_VTY,
				.chan_mode = GSM48_CMODE_SIGN,
				.requires_voice_stream = false,
			};
		} else {
			vty_out(vty, "%% Invalid channel mode specified!%s", VTY_NEWLINE);
			return CMD_WARNING;
		}

		vty_out(vty, "%% activating lchan %s as %s%s", gsm_lchan_name(lchan), gsm_chan_t_name(lchan->type),
			VTY_NEWLINE);
		lchan_activate(lchan, &info);
	} else {
		LOG_LCHAN(lchan, LOGL_NOTICE, "attempt from VTY to release lchan %s\n", gsm_lchan_name(lchan));
		if (!lchan->fi) {
			vty_out(vty, "%% Cannot release: Channel not initialized%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		vty_out(vty, "%% Asking for release of %s in state %s%s", gsm_lchan_name(lchan),
			osmo_fsm_inst_state_name(lchan->fi), VTY_NEWLINE);
		lchan_release(lchan, !!(lchan->conn), false, 0);
	}

	return CMD_SUCCESS;
}

/* Activate / Deactivate a single lchan with a specific codec mode */
static int lchan_act_trx(struct vty *vty, struct gsm_bts_trx *trx, int activate)
{
	int ts_nr;
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	char *codec_str;
	bool skip_next = false;

	for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
		ts = &trx->ts[ts_nr];
		ts_for_each_potential_lchan(lchan, ts) {
			switch (ts->pchan_on_init) {
			case GSM_PCHAN_SDCCH8_SACCH8C:
			case GSM_PCHAN_CCCH_SDCCH4_CBCH:
			case GSM_PCHAN_SDCCH8_SACCH8C_CBCH:
			case GSM_PCHAN_CCCH:
			case GSM_PCHAN_CCCH_SDCCH4:
				codec_str = "sig";
				break;
			case GSM_PCHAN_TCH_F:
			case GSM_PCHAN_TCH_F_PDCH:
			case GSM_PCHAN_TCH_F_TCH_H_PDCH:
				codec_str = "fr";
				break;
			case GSM_PCHAN_TCH_H:
				codec_str = "hr";
				break;
			default:
				codec_str = NULL;
			}

			if (codec_str && skip_next == false) {
				lchan_act_single(vty, lchan, codec_str, -1, activate);

				/* We use GSM_PCHAN_TCH_F_TCH_H_PDCH slots as TCH_F for this test, so we
				 * must not use the TCH_H reserved lchan in subslot 1. */
				if (ts->pchan_on_init == GSM_PCHAN_TCH_F_TCH_H_PDCH)
					skip_next = true;
			}
			else {
				vty_out(vty, "%% omitting lchan %s%s", gsm_lchan_name(lchan), VTY_NEWLINE);
				skip_next = false;
			}
		}
	}

	return CMD_SUCCESS;
}

/* Debug/Measurement command to activate a given logical channel
 * manually in a given mode/codec.  This is useful for receiver
 * performance testing (FER/RBER/...) */
DEFUN(lchan_act, lchan_act_cmd,
	"bts <0-255> trx <0-255> timeslot <0-7> sub-slot <0-7> (activate|deactivate) (hr|fr|efr|amr|sig) [<0-7>]",
	BTS_NR_TRX_TS_SS_STR2
	"Manual Channel Activation (e.g. for BER test)\n"
	"Manual Channel Deactivation (e.g. for BER test)\n"
	"Half-Rate v1\n" "Full-Rate\n" "Enhanced Full Rate\n" "Adaptive Multi-Rate\n" "Signalling\n" "AMR Mode\n")
{
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	int ss_nr = atoi(argv[3]);
	const char *act_str = argv[4];
	const char *codec_str = argv[5];
	int activate;
	int amr_mode = -1;

	if (argc > 6)
		amr_mode = atoi(argv[6]);

	ts = vty_get_ts(vty, argv[0], argv[1], argv[2]);
	if (!ts)
		return CMD_WARNING;

	lchan = &ts->lchan[ss_nr];

	if (!strcmp(act_str, "activate"))
		activate = 1;
	else
		activate = 0;

	return lchan_act_single(vty, lchan, codec_str, amr_mode, activate);
}

#define ACTIVATE_ALL_LCHANS_STR "Manual Channel Activation of all logical channels (e.g. for BER test)\n"
#define DEACTIVATE_ALL_LCHANS_STR "Manual Channel Deactivation of all logical channels (e.g. for BER test)\n"

/* Similar to lchan_act, but activates all lchans on the network at once,
 * this is intended to perform lab tests / measurements. */
DEFUN_HIDDEN(lchan_act_bts, lchan_act_all_cmd,
	     "(activate-all-lchan|deactivate-all-lchan)",
	     ACTIVATE_ALL_LCHANS_STR
	     DEACTIVATE_ALL_LCHANS_STR)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	const char *act_str = argv[0];
	int activate;
	int bts_nr;
	struct gsm_bts *bts;
	int trx_nr;
	struct gsm_bts_trx *trx;

	if (!strcmp(act_str, "activate-all-lchan"))
		activate = 1;
	else
		activate = 0;

	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = gsm_bts_trx_num(bts, trx_nr);
			lchan_act_trx(vty, trx, activate);
		}
	}

	vty_out(vty, "%% All channels have been %s on all BTS/TRX, please "
		     "make sure that the radio link timeout is set to %s%s",
		activate ? "activated" : "deactivated",
		activate ? "'infinite'" : "its old value (e.g. 'oml')",
		VTY_NEWLINE);

	return CMD_SUCCESS;
}

/* Similar to lchan_act, but activates all lchans on the specified BTS at once,
 * this is intended to perform lab tests / measurements. */
DEFUN_HIDDEN(lchan_act_all_bts, lchan_act_all_bts_cmd,
	     "bts <0-255> (activate-all-lchan|deactivate-all-lchan)",
	     "BTS Specific Commands\n" BTS_NR_STR
	     ACTIVATE_ALL_LCHANS_STR
	     DEACTIVATE_ALL_LCHANS_STR)
{
	int bts_nr = atoi(argv[0]);
	const char *act_str = argv[1];
	int activate;
	struct gsm_bts *bts;
	int trx_nr;
	struct gsm_bts_trx *trx;

	if (!strcmp(act_str, "activate-all-lchan"))
		activate = 1;
	else
		activate = 0;

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
		trx = gsm_bts_trx_num(bts, trx_nr);
		lchan_act_trx(vty, trx, activate);
	}

	vty_out(vty, "%% All channels have been %s on all TRX of BTS%d, please "
		     "make sure that the radio link timeout is set to %s%s",
		activate ? "activated" : "deactivated", bts_nr,
		activate ? "'infinite'" : "its old value (e.g. 'oml')",
		VTY_NEWLINE);

	return CMD_SUCCESS;
}

/* Similar to lchan_act, but activates all lchans on the specified BTS at once,
 * this is intended to perform lab tests / measurements. */
DEFUN_HIDDEN(lchan_act_all_trx, lchan_act_all_trx_cmd,
	     "bts <0-255> trx <0-255> (activate-all-lchan|deactivate-all-lchan)",
	     "BTS for manual command\n" BTS_NR_STR
	     "TRX for manual command\n" TRX_NR_STR
	     ACTIVATE_ALL_LCHANS_STR
	     DEACTIVATE_ALL_LCHANS_STR)
{
	int bts_nr = atoi(argv[0]);
	int trx_nr = atoi(argv[1]);
	const char *act_str = argv[2];
	int activate;
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;

	if (!strcmp(act_str, "activate-all-lchan"))
		activate = 1;
	else
		activate = 0;

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	trx = gsm_bts_trx_num(bts, trx_nr);
	if (!trx) {
		vty_out(vty, "%% No such TRX (%d)%s", trx_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	lchan_act_trx(vty, trx, activate);

	vty_out(vty, "%% All channels have been %s on BTS%d/TRX%d, please "
		     "make sure that the radio link timeout is set to %s%s",
		activate ? "activated" : "deactivated", bts_nr, trx_nr,
		activate ? "'infinite'" : "its old value (e.g. 'oml')",
		VTY_NEWLINE);

	return CMD_SUCCESS;
}

/* Debug command to send lchans from state LCHAN_ST_UNUSED to state
 * LCHAN_ST_BORKEN and vice versa. */
DEFUN_HIDDEN(lchan_set_borken, lchan_set_borken_cmd,
	     "bts <0-255> trx <0-255> timeslot <0-7> sub-slot <0-7> (borken|unused)",
	     BTS_NR_TRX_TS_SS_STR2
	     "send lchan to state LCHAN_ST_BORKEN (for debugging)\n"
	     "send lchan to state LCHAN_ST_UNUSED (for debugging)\n")
{
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	int ss_nr = atoi(argv[3]);
	ts = vty_get_ts(vty, argv[0], argv[1], argv[2]);
	if (!ts)
		return CMD_WARNING;

	lchan = &ts->lchan[ss_nr];
	if (!lchan->fi)
		return CMD_WARNING;

	if (!strcmp(argv[4], "borken")) {
		if (lchan->fi->state == LCHAN_ST_UNUSED) {
			osmo_fsm_inst_state_chg(lchan->fi, LCHAN_ST_BORKEN, 0, 0);
		} else {
			vty_out(vty,
				"%% lchan is in state %s, only lchans that are in state %s may be moved to state %s manually%s",
				osmo_fsm_state_name(lchan->fi->fsm, lchan->fi->state),
				osmo_fsm_state_name(lchan->fi->fsm, LCHAN_ST_UNUSED),
				osmo_fsm_state_name(lchan->fi->fsm, LCHAN_ST_BORKEN), VTY_NEWLINE);
			return CMD_WARNING;
		}
	} else {
		if (lchan->fi->state == LCHAN_ST_BORKEN) {
			rate_ctr_inc(&lchan->ts->trx->bts->bts_ctrs->ctr[BTS_CTR_LCHAN_BORKEN_EV_VTY]);
			osmo_fsm_inst_state_chg(lchan->fi, LCHAN_ST_UNUSED, 0, 0);
		} else {
			vty_out(vty,
				"%% lchan is in state %s, only lchans that are in state %s may be moved to state %s manually%s",
				osmo_fsm_state_name(lchan->fi->fsm, lchan->fi->state),
				osmo_fsm_state_name(lchan->fi->fsm, LCHAN_ST_BORKEN),
				osmo_fsm_state_name(lchan->fi->fsm, LCHAN_ST_UNUSED), VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

DEFUN(lchan_mdcx, lchan_mdcx_cmd,
	"bts <0-255> trx <0-255> timeslot <0-7> sub-slot <0-7> mdcx A.B.C.D <0-65535>",
	BTS_NR_TRX_TS_SS_STR2
	"Modify RTP Connection\n" "MGW IP Address\n" "MGW UDP Port\n")
{
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	int ss_nr = atoi(argv[3]);
	int port = atoi(argv[5]);
	struct in_addr ia;
	inet_aton(argv[4], &ia);

	ts = vty_get_ts(vty, argv[0], argv[1], argv[2]);
	if (!ts)
		return CMD_WARNING;

	lchan = &ts->lchan[ss_nr];

	if (!is_ipaccess_bts(lchan->ts->trx->bts)) {
		vty_out(vty, "%% BTS is not of ip.access type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (ss_nr >= pchan_subslots(ts->pchan_is)) {
		vty_out(vty, "%% subslot index %d too large for physical channel %s (%u slots)%s",
			ss_nr, gsm_pchan_name(ts->pchan_is), pchan_subslots(ts->pchan_is),
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "%% connecting RTP of %s to %s:%u%s", gsm_lchan_name(lchan),
		inet_ntoa(ia), port, VTY_NEWLINE);
	lchan->abis_ip.connect_ip = ia.s_addr;
	lchan->abis_ip.connect_port = port;
	rsl_tx_ipacc_mdcx(lchan);
	return CMD_SUCCESS;
}

DEFUN(ctrl_trap, ctrl_trap_cmd,
	"ctrl-interface generate-trap TRAP VALUE",
	"Commands related to the CTRL Interface\n"
	"Generate a TRAP for test purpose\n"
	"Identity/Name of the TRAP variable\n"
	"Value of the TRAP variable\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	ctrl_cmd_send_trap(net->ctrl, argv[0], (char *) argv[1]);
	return CMD_SUCCESS;
}

#define NETWORK_STR "Configure the GSM network\n"
#define CODE_CMD_STR "Code commands\n"
#define NAME_CMD_STR "Name Commands\n"
#define NAME_STR "Name to use\n"

DEFUN_ATTR(cfg_net,
	   cfg_net_cmd,
	   "network", NETWORK_STR,
	   CMD_ATTR_IMMEDIATE)
{
	vty->index = gsmnet_from_vty(vty);
	vty->node = GSMNET_NODE;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_ncc,
	      cfg_net_ncc_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "network country code <1-999>",
	      "Set the GSM network country code\n"
	      "Country commands\n"
	      CODE_CMD_STR
	      "Network Country Code to use\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	uint16_t mcc;

	if (osmo_mcc_from_str(argv[0], &mcc)) {
		vty_out(vty, "%% Error decoding MCC: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gsmnet->plmn.mcc = mcc;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_mnc,
	      cfg_net_mnc_cmd,
	      X(BSC_VTY_ATTR_RESTART_ABIS_RSL_LINK),
	      "mobile network code <0-999>",
	      "Set the GSM mobile network code\n"
	      "Network Commands\n"
	      CODE_CMD_STR
	      "Mobile Network Code to use\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	uint16_t mnc;
	bool mnc_3_digits;

	if (osmo_mnc_from_str(argv[0], &mnc, &mnc_3_digits)) {
		vty_out(vty, "%% Error decoding MNC: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	gsmnet->plmn.mnc = mnc;
	gsmnet->plmn.mnc_3_digits = mnc_3_digits;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_encryption,
	      cfg_net_encryption_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "encryption a5 <0-3> [<0-3>] [<0-3>] [<0-3>]",
	      "Encryption options\n"
	      "GSM A5 Air Interface Encryption\n"
	      "A5/n Algorithm Number\n"
	      "A5/n Algorithm Number\n"
	      "A5/n Algorithm Number\n"
	      "A5/n Algorithm Number\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	unsigned int i;

	gsmnet->a5_encryption_mask = 0;
	for (i = 0; i < argc; i++)
		gsmnet->a5_encryption_mask |= (1 << atoi(argv[i]));

	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_net_dyn_ts_allow_tch_f,
      cfg_net_dyn_ts_allow_tch_f_cmd,
      "dyn_ts_allow_tch_f (0|1)",
      "Allow or disallow allocating TCH/F on TCH_F_TCH_H_PDCH timeslots\n"
      "Disallow TCH/F on TCH_F_TCH_H_PDCH (default)\n"
      "Allow TCH/F on TCH_F_TCH_H_PDCH\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->dyn_ts_allow_tch_f = atoi(argv[0]) ? true : false;
	vty_out(vty, "%% dyn_ts_allow_tch_f is deprecated, rather use msc/codec-list to pick codecs%s",
		VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_timezone,
	   cfg_net_timezone_cmd,
	   "timezone <-19-19> (0|15|30|45)",
	   "Set the Timezone Offset of the network\n"
	   "Timezone offset (hours)\n"
	   "Timezone offset (00 minutes)\n"
	   "Timezone offset (15 minutes)\n"
	   "Timezone offset (30 minutes)\n"
	   "Timezone offset (45 minutes)\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_network *net = vty->index;
	int tzhr = atoi(argv[0]);
	int tzmn = atoi(argv[1]);

	net->tz.hr = tzhr;
	net->tz.mn = tzmn;
	net->tz.dst = 0;
	net->tz.override = 1;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_timezone_dst,
	   cfg_net_timezone_dst_cmd,
	   "timezone <-19-19> (0|15|30|45) <0-2>",
	   "Set the Timezone Offset of the network\n"
	   "Timezone offset (hours)\n"
	   "Timezone offset (00 minutes)\n"
	   "Timezone offset (15 minutes)\n"
	   "Timezone offset (30 minutes)\n"
	   "Timezone offset (45 minutes)\n"
	   "DST offset (hours)\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_network *net = vty->index;
	int tzhr = atoi(argv[0]);
	int tzmn = atoi(argv[1]);
	int tzdst = atoi(argv[2]);

	net->tz.hr = tzhr;
	net->tz.mn = tzmn;
	net->tz.dst = tzdst;
	net->tz.override = 1;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_no_timezone,
	   cfg_net_no_timezone_cmd,
	   "no timezone",
	   NO_STR
	   "Disable network timezone override, use system tz\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gsm_network *net = vty->index;

	net->tz.override = 0;

	return CMD_SUCCESS;
}

/* FIXME: changing this value would not affect generated System Information */
DEFUN(cfg_net_per_loc_upd, cfg_net_per_loc_upd_cmd,
      "periodic location update <6-1530>",
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval in Minutes\n")
{
	struct gsm_network *net = vty->index;
	struct osmo_tdef *d = osmo_tdef_get_entry(net->T_defs, 3212);

	OSMO_ASSERT(d);
	d->val = atoi(argv[0]) / 6;
	vty_out(vty, "T%d = %lu %s (%s)%s", d->T, d->val, "* 6min", d->desc, VTY_NEWLINE);
	return CMD_SUCCESS;
}

/* FIXME: changing this value would not affect generated System Information */
DEFUN(cfg_net_no_per_loc_upd, cfg_net_no_per_loc_upd_cmd,
      "no periodic location update",
      NO_STR
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n")
{
	struct gsm_network *net = vty->index;
	struct osmo_tdef *d = osmo_tdef_get_entry(net->T_defs, 3212);

	OSMO_ASSERT(d);
	d->val = 0;
	vty_out(vty, "T%d = %lu %s (%s)%s", d->T, d->val, "* 6min", d->desc, VTY_NEWLINE);
	return CMD_SUCCESS;
}

#define MEAS_FEED_STR "Measurement Report export\n"

DEFUN_ATTR(cfg_net_meas_feed_dest, cfg_net_meas_feed_dest_cmd,
	   "meas-feed destination ADDR <0-65535>",
	   MEAS_FEED_STR "Where to forward Measurement Report feeds\n" "address or hostname\n" "port number\n",
	   CMD_ATTR_IMMEDIATE)
{
	int rc;
	const char *host = argv[0];
	uint16_t port = atoi(argv[1]);

	rc = meas_feed_cfg_set(host, port);
	if (rc < 0)
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_meas_feed_scenario, cfg_net_meas_feed_scenario_cmd,
	   "meas-feed scenario NAME",
	   MEAS_FEED_STR "Set a name to include in the Measurement Report feeds\n" "Name string, up to 31 characters\n",
	   CMD_ATTR_IMMEDIATE)
{
	meas_feed_scenario_set(argv[0]);

	return CMD_SUCCESS;
}

static void legacy_timers(struct vty *vty, const char **T_arg)
{
	if (!strcmp((*T_arg), "T993111") || !strcmp((*T_arg), "t993111")) {
		vty_out(vty, "%% Legacy: timer T993111 is now X3111%s", VTY_NEWLINE);
		(*T_arg) = "X3111";
	} else if (!strcmp((*T_arg), "T993210") || !strcmp((*T_arg), "t993210")) {
		vty_out(vty, "%% Legacy: timer T993210 is now X3210%s", VTY_NEWLINE);
		(*T_arg) = "X3210";
	} else if (!strcmp((*T_arg), "T999") || !strcmp((*T_arg), "t999")) {
		vty_out(vty, "%% Legacy: timer T999 is now X4%s", VTY_NEWLINE);
		(*T_arg) = "X4";
	}
}

/* LEGACY TIMER COMMAND. The proper commands are added by osmo_tdef_vty_groups_init(), using explicit timer group
 * naming. The old groupless timer command accesses the 'net' group only, but is still available. */
DEFUN_HIDDEN(show_timer, show_timer_cmd,
      "show timer " OSMO_TDEF_VTY_ARG_T,
      SHOW_STR "Show timers\n"
      OSMO_TDEF_VTY_DOC_T)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	const char *T_arg = argv[0];
	if (T_arg)
		legacy_timers(vty, &T_arg);
	return osmo_tdef_vty_show_cmd(vty, net->T_defs, T_arg, NULL);
}

/* LEGACY TIMER COMMAND. The proper commands are added by osmo_tdef_vty_groups_init(), using explicit timer group
 * naming. The old groupless timer command accesses the 'net' group only, but is still available. */
DEFUN_HIDDEN(cfg_net_timer, cfg_net_timer_cmd,
      "timer " OSMO_TDEF_VTY_ARG_T " " OSMO_TDEF_VTY_ARG_VAL_OPTIONAL,
      "Configure or show timers\n"
      OSMO_TDEF_VTY_DOC_SET)
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	const char *mod_argv[argc];
	memcpy(mod_argv, argv, sizeof(mod_argv));
	legacy_timers(vty, &mod_argv[0]);
	/* If any arguments are missing, redirect to 'show' */
	if (argc < 2)
		return show_timer(self, vty, argc, mod_argv);
	return osmo_tdef_vty_set_cmd(vty, net->T_defs, mod_argv);
}

DEFUN(cfg_net_allow_unusable_timeslots, cfg_net_allow_unusable_timeslots_cmd,
      "allow-unusable-timeslots",
      "Don't refuse to start with mutually exclusive codec settings\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	net->allow_unusable_timeslots = true;
	LOGP(DMSC, LOGL_ERROR, "Configuration contains 'allow-unusable-timeslots'. OsmoBSC will start up even if the"
			       " configuration has unusable codec settings!\n");
	return CMD_SUCCESS;
}

static struct bsc_msc_data *bsc_msc_data(struct vty *vty)
{
	return vty->index;
}

static struct cmd_node bsc_node = {
	BSC_NODE,
	"%s(config-bsc)# ",
	1,
};

static struct cmd_node msc_node = {
	MSC_NODE,
	"%s(config-msc)# ",
	1,
};

#define MSC_NR_RANGE "<0-1000>"

DEFUN_ATTR(cfg_net_msc,
	   cfg_net_msc_cmd,
	   "msc [" MSC_NR_RANGE "]", "Configure MSC details\n" "MSC connection to configure\n",
	   CMD_ATTR_IMMEDIATE)
{
	int index = argc == 1 ? atoi(argv[0]) : 0;
	struct bsc_msc_data *msc;

	msc = osmo_msc_data_alloc(bsc_gsmnet, index);
	if (!msc) {
		vty_out(vty, "%% Failed to allocate MSC data.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->index = msc;
	vty->node = MSC_NODE;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_bsc,
	   cfg_net_bsc_cmd,
	   "bsc", "Configure BSC\n",
	   CMD_ATTR_IMMEDIATE)
{
	vty->node = BSC_NODE;
	return CMD_SUCCESS;
}

static void write_msc_amr_options(struct vty *vty, struct bsc_msc_data *msc)
{
#define WRITE_AMR(vty, msc, name, var) \
	vty_out(vty, " amr-config %s %s%s", \
		name, msc->amr_conf.var ? "allowed" : "forbidden", \
		VTY_NEWLINE);

	WRITE_AMR(vty, msc, "12_2k", m12_2);
	WRITE_AMR(vty, msc, "10_2k", m10_2);
	WRITE_AMR(vty, msc, "7_95k", m7_95);
	WRITE_AMR(vty, msc, "7_40k", m7_40);
	WRITE_AMR(vty, msc, "6_70k", m6_70);
	WRITE_AMR(vty, msc, "5_90k", m5_90);
	WRITE_AMR(vty, msc, "5_15k", m5_15);
	WRITE_AMR(vty, msc, "4_75k", m4_75);
#undef WRITE_AMR

	if (msc->amr_octet_aligned)
		vty_out(vty, " amr-payload octet-aligned%s", VTY_NEWLINE);
	else
		vty_out(vty, " amr-payload bandwith-efficient%s", VTY_NEWLINE);
}

static void msc_write_nri(struct vty *vty, struct bsc_msc_data *msc, bool verbose);

static void write_msc(struct vty *vty, struct bsc_msc_data *msc)
{
	vty_out(vty, "msc %d%s", msc->nr, VTY_NEWLINE);
	if (msc->core_plmn.mnc != GSM_MCC_MNC_INVALID)
		vty_out(vty, " core-mobile-network-code %s%s",
			osmo_mnc_name(msc->core_plmn.mnc, msc->core_plmn.mnc_3_digits), VTY_NEWLINE);
	if (msc->core_plmn.mcc != GSM_MCC_MNC_INVALID)
		vty_out(vty, " core-mobile-country-code %s%s",
			osmo_mcc_name(msc->core_plmn.mcc), VTY_NEWLINE);

	if (msc->audio_length != 0) {
		int i;

		vty_out(vty, " codec-list ");
		for (i = 0; i < msc->audio_length; ++i) {
			if (i != 0)
				vty_out(vty, " ");

			if (msc->audio_support[i]->hr)
				vty_out(vty, "hr%.1u", msc->audio_support[i]->ver);
			else
				vty_out(vty, "fr%.1u", msc->audio_support[i]->ver);
		}
		vty_out(vty, "%s", VTY_NEWLINE);

	}

	vty_out(vty, " allow-emergency %s%s", msc->allow_emerg ?
					"allow" : "deny", VTY_NEWLINE);

	/* write amr options */
	write_msc_amr_options(vty, msc);

	/* write sccp connection configuration */
	if (msc->a.bsc_addr_name) {
		vty_out(vty, " bsc-addr %s%s",
			msc->a.bsc_addr_name, VTY_NEWLINE);
	}
	if (msc->a.msc_addr_name) {
		vty_out(vty, " msc-addr %s%s",
			msc->a.msc_addr_name, VTY_NEWLINE);
	}
	vty_out(vty, " asp-protocol %s%s", osmo_ss7_asp_protocol_name(msc->a.asp_proto), VTY_NEWLINE);
	vty_out(vty, " lcls-mode %s%s", get_value_string(bsc_lcls_mode_names, msc->lcls_mode),
		VTY_NEWLINE);

	if (msc->lcls_codec_mismatch_allow)
		vty_out(vty, " lcls-codec-mismatch allowed%s", VTY_NEWLINE);
	else
		vty_out(vty, " lcls-codec-mismatch forbidden%s", VTY_NEWLINE);

	/* write MGW configuration */
	mgcp_client_config_write(vty, " ");

	if (msc->x_osmo_ign_configured) {
		if (!msc->x_osmo_ign)
			vty_out(vty, " no mgw x-osmo-ign%s", VTY_NEWLINE);
		else
			vty_out(vty, " mgw x-osmo-ign call-id%s", VTY_NEWLINE);
	}

	if (msc->use_osmux != OSMUX_USAGE_OFF) {
		vty_out(vty, " osmux %s%s", msc->use_osmux == OSMUX_USAGE_ON ? "on" : "only",
			VTY_NEWLINE);
	}

	msc_write_nri(vty, msc, false);

	if (!msc->allow_attach)
		vty_out(vty, " no allow-attach%s", VTY_NEWLINE);
}

static int config_write_msc(struct vty *vty)
{
	struct bsc_msc_data *msc;

	llist_for_each_entry(msc, &bsc_gsmnet->mscs, entry)
		write_msc(vty, msc);

	return CMD_SUCCESS;
}

static int config_write_bsc(struct vty *vty)
{
	vty_out(vty, "bsc%s", VTY_NEWLINE);
	vty_out(vty, " mid-call-timeout %d%s", bsc_gsmnet->mid_call_timeout, VTY_NEWLINE);
	if (bsc_gsmnet->rf_ctrl_name)
		vty_out(vty, " bsc-rf-socket %s%s",
			bsc_gsmnet->rf_ctrl_name, VTY_NEWLINE);

	if (bsc_gsmnet->auto_off_timeout != -1)
		vty_out(vty, " bsc-auto-rf-off %d%s",
			bsc_gsmnet->auto_off_timeout, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_bsc_ncc,
	   cfg_net_bsc_ncc_cmd,
	   "core-mobile-network-code <1-999>",
	   "Use this network code for the core network\n" "MNC value\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	uint16_t mnc;
	bool mnc_3_digits;

	if (osmo_mnc_from_str(argv[0], &mnc, &mnc_3_digits)) {
		vty_out(vty, "%% Error decoding MNC: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	data->core_plmn.mnc = mnc;
	data->core_plmn.mnc_3_digits = mnc_3_digits;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_bsc_mcc,
	   cfg_net_bsc_mcc_cmd,
	   "core-mobile-country-code <1-999>",
	   "Use this country code for the core network\n" "MCC value\n",
	   CMD_ATTR_IMMEDIATE)
{
	uint16_t mcc;
	struct bsc_msc_data *data = bsc_msc_data(vty);
	if (osmo_mcc_from_str(argv[0], &mcc)) {
		vty_out(vty, "%% Error decoding MCC: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	data->core_plmn.mcc = mcc;
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_net_bsc_lac,
		 cfg_net_bsc_lac_cmd,
		 "core-location-area-code <0-65535>",
		 "Legacy configuration that no longer has any effect\n-\n")
{
	vty_out(vty, "%% Deprecated 'core-location-area-code' config no longer has any effect%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_net_bsc_ci,
		 cfg_net_bsc_ci_cmd,
		 "core-cell-identity <0-65535>",
		 "Legacy configuration that no longer has any effect\n-\n")
{
	vty_out(vty, "%% Deprecated 'core-cell-identity' config no longer has any effect%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_net_bsc_rtp_base,
      cfg_net_bsc_rtp_base_cmd,
      "ip.access rtp-base <1-65000>",
      "deprecated\n" "deprecated, RTP is handled by the MGW\n" "deprecated\n")
{
	vty_out(vty, "%% deprecated: 'ip.access rtp-base' has no effect, RTP is handled by the MGW%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_bsc_codec_list,
	      cfg_net_bsc_codec_list_cmd,
	      BSC_VTY_ATTR_NEW_LCHAN,
	      "codec-list .LIST",
	      "Set the allowed audio codecs\n"
	      "List of audio codecs, e.g. fr3 fr1 hr3\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	int i;

	/* check all given arguments first */
	for (i = 0; i < argc; ++i) {
		/* check for hrX or frX */
		if (strlen(argv[i]) != 3
				|| argv[i][1] != 'r'
				|| (argv[i][0] != 'h' && argv[i][0] != 'f')
				|| argv[i][2] < 0x30
				|| argv[i][2] > 0x39)
			goto error;
	}

	/* free the old list... if it exists */
	if (data->audio_support) {
		talloc_free(data->audio_support);
		data->audio_support = NULL;
		data->audio_length = 0;
	}

	/* create a new array */
	data->audio_support =
		talloc_zero_array(bsc_gsmnet, struct gsm_audio_support *, argc);
	data->audio_length = argc;

	for (i = 0; i < argc; ++i) {
		data->audio_support[i] = talloc_zero(data->audio_support,
				struct gsm_audio_support);
		data->audio_support[i]->ver = atoi(argv[i] + 2);

		if (strncmp("hr", argv[i], 2) == 0)
			data->audio_support[i]->hr = 1;
		else if (strncmp("fr", argv[i], 2) == 0)
			data->audio_support[i]->hr = 0;
	}

	return CMD_SUCCESS;

error:
	vty_out(vty, "Codec name must be hrX or frX. Was '%s'%s",
			argv[i], VTY_NEWLINE);
	return CMD_ERR_INCOMPLETE;
}

#define LEGACY_STR "This command has no effect, it is kept to support legacy config files\n"

DEFUN_DEPRECATED(deprecated_ussd_text,
      cfg_net_msc_welcome_ussd_cmd,
      "bsc-welcome-text .TEXT", LEGACY_STR LEGACY_STR)
{
	vty_out(vty, "%% osmo-bsc no longer supports USSD notification. These commands have no effect:%s"
		"%%   bsc-welcome-text, bsc-msc-lost-text, mid-call-text, bsc-grace-text, missing-msc-text%s",
		VTY_NEWLINE, VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN_DEPRECATED(deprecated_no_ussd_text,
      cfg_net_msc_no_welcome_ussd_cmd,
      "no bsc-welcome-text",
      NO_STR LEGACY_STR)
{
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(deprecated_ussd_text,
      cfg_net_msc_lost_ussd_cmd,
      "bsc-msc-lost-text .TEXT", LEGACY_STR LEGACY_STR);

ALIAS_DEPRECATED(deprecated_no_ussd_text,
      cfg_net_msc_no_lost_ussd_cmd,
      "no bsc-msc-lost-text", NO_STR LEGACY_STR);

ALIAS_DEPRECATED(deprecated_ussd_text,
      cfg_net_msc_grace_ussd_cmd,
      "bsc-grace-text .TEXT", LEGACY_STR LEGACY_STR);

ALIAS_DEPRECATED(deprecated_no_ussd_text,
      cfg_net_msc_no_grace_ussd_cmd,
      "no bsc-grace-text", NO_STR LEGACY_STR);

ALIAS_DEPRECATED(deprecated_ussd_text,
      cfg_net_bsc_missing_msc_ussd_cmd,
      "missing-msc-text .TEXT", LEGACY_STR LEGACY_STR);

ALIAS_DEPRECATED(deprecated_no_ussd_text,
      cfg_net_bsc_no_missing_msc_text_cmd,
      "no missing-msc-text", NO_STR LEGACY_STR);

DEFUN_DEPRECATED(cfg_net_msc_type,
      cfg_net_msc_type_cmd,
      "type (normal|local)",
      LEGACY_STR LEGACY_STR)
{
	vty_out(vty, "%% 'msc' / 'type' config is deprecated and no longer has any effect%s",
		VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_msc_emerg,
	   cfg_net_msc_emerg_cmd,
	   "allow-emergency (allow|deny)",
	   "Allow CM ServiceRequests with type emergency\n"
	   "Allow\n" "Deny\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	data->allow_emerg = strcmp("allow", argv[0]) == 0;
	return CMD_SUCCESS;
}

#define AMR_CONF_STR "AMR Multirate Configuration\n"
#define AMR_COMMAND(name) \
	DEFUN_USRATTR(cfg_net_msc_amr_##name,				\
	  cfg_net_msc_amr_##name##_cmd,BSC_VTY_ATTR_NEW_LCHAN, 		\
	  "amr-config " #name "k (allowed|forbidden)",			\
	  AMR_CONF_STR "Bitrate\n" "Allowed\n" "Forbidden\n")		\
{									\
	struct bsc_msc_data *msc = bsc_msc_data(vty);			\
									\
	msc->amr_conf.m##name = strcmp(argv[0], "allowed") == 0;	\
	return CMD_SUCCESS;						\
}

AMR_COMMAND(12_2)
AMR_COMMAND(10_2)
AMR_COMMAND(7_95)
AMR_COMMAND(7_40)
AMR_COMMAND(6_70)
AMR_COMMAND(5_90)
AMR_COMMAND(5_15)
AMR_COMMAND(4_75)

/* Make sure only standard SSN numbers are used. If no ssn number is
 * configured, silently apply the default SSN */
static void enforce_standard_ssn(struct vty *vty, struct osmo_sccp_addr *addr)
{
	if (addr->presence & OSMO_SCCP_ADDR_T_SSN) {
		if (addr->ssn != OSMO_SCCP_SSN_BSSAP)
			vty_out(vty,
				"setting an SSN (%u) different from the standard (%u) is not allowed, will use standard SSN for address: %s%s",
				addr->ssn, OSMO_SCCP_SSN_BSSAP, osmo_sccp_addr_dump(addr), VTY_NEWLINE);
	}

	addr->presence |= OSMO_SCCP_ADDR_T_SSN;
	addr->ssn = OSMO_SCCP_SSN_BSSAP;
}

DEFUN(cfg_msc_cs7_bsc_addr,
      cfg_msc_cs7_bsc_addr_cmd,
      "bsc-addr NAME",
      "Calling Address (local address of this BSC)\n" "SCCP address name\n")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	const char *bsc_addr_name = argv[0];
	struct osmo_ss7_instance *ss7;

	ss7 = osmo_sccp_addr_by_name(&msc->a.bsc_addr, bsc_addr_name);
	if (!ss7) {
		vty_out(vty, "Error: No such SCCP addressbook entry: '%s'%s", bsc_addr_name, VTY_NEWLINE);
		return CMD_ERR_INCOMPLETE;
	}

	/* Prevent mixing addresses from different CS7/SS7 instances */
	if (msc->a.cs7_instance_valid) {
		if (msc->a.cs7_instance != ss7->cfg.id) {
			vty_out(vty,
				"Error: SCCP addressbook entry from mismatching CS7 instance: '%s'%s",
				bsc_addr_name, VTY_NEWLINE);
			return CMD_ERR_INCOMPLETE;
		}
	}

	msc->a.cs7_instance = ss7->cfg.id;
	msc->a.cs7_instance_valid = true;
	enforce_standard_ssn(vty, &msc->a.bsc_addr);
	msc->a.bsc_addr_name = talloc_strdup(msc, bsc_addr_name);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_cs7_msc_addr,
      cfg_msc_cs7_msc_addr_cmd,
      "msc-addr NAME",
      "Called Address (remote address of the MSC)\n" "SCCP address name\n")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	const char *msc_addr_name = argv[0];
	struct osmo_ss7_instance *ss7;

	ss7 = osmo_sccp_addr_by_name(&msc->a.msc_addr, msc_addr_name);
	if (!ss7) {
		vty_out(vty, "Error: No such SCCP addressbook entry: '%s'%s", msc_addr_name, VTY_NEWLINE);
		return CMD_ERR_INCOMPLETE;
	}

	/* Prevent mixing addresses from different CS7/SS7 instances */
	if (msc->a.cs7_instance_valid) {
		if (msc->a.cs7_instance != ss7->cfg.id) {
			vty_out(vty,
				"Error: SCCP addressbook entry from mismatching CS7 instance: '%s'%s",
				msc_addr_name, VTY_NEWLINE);
			return CMD_ERR_INCOMPLETE;
		}
	}

	msc->a.cs7_instance = ss7->cfg.id;
	msc->a.cs7_instance_valid = true;
	enforce_standard_ssn(vty, &msc->a.msc_addr);
	msc->a.msc_addr_name = talloc_strdup(msc, msc_addr_name);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_cs7_asp_proto,
      cfg_msc_cs7_asp_proto_cmd,
      "asp-protocol (m3ua|sua|ipa)",
      "A interface protocol to use for this MSC)\n"
      "MTP3 User Adaptation\n"
      "SCCP User Adaptation\n"
      "IPA Multiplex (SCCP Lite)\n")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);

	msc->a.asp_proto = get_string_value(osmo_ss7_asp_protocol_vals, argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_msc_lcls_mode,
	      cfg_net_msc_lcls_mode_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "lcls-mode (disabled|mgw-loop|bts-loop)",
	      "Configure 3GPP LCLS (Local Call, Local Switch)\n"
	      "Disable LCLS for all calls of this MSC\n"
	      "Enable LCLS with looping traffic in MGW\n"
	      "Enable LCLS with looping traffic between BTS\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	data->lcls_mode = get_string_value(bsc_lcls_mode_names, argv[0]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_net_msc_lcls_mismtch,
	      cfg_net_msc_lcls_mismtch_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "lcls-codec-mismatch (allowed|forbidden)",
	      "Allow 3GPP LCLS (Local Call, Local Switch) when call legs use different codec/rate\n"
	      "Allow LCLS only only for calls that use the same codec/rate on both legs\n"
	      "Do not Allow LCLS for calls that use a different codec/rate on both legs\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);

	if (strcmp(argv[0], "allowed") == 0)
		data->lcls_codec_mismatch_allow = true;
	else
		data->lcls_codec_mismatch_allow = false;

	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_msc_mgw_x_osmo_ign,
	      cfg_msc_mgw_x_osmo_ign_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "mgw x-osmo-ign call-id",
	      MGCP_CLIENT_MGW_STR
	      "Set a (non-standard) X-Osmo-IGN header in all CRCX messages for RTP streams"
	      " associated with this MSC, useful for A/SCCPlite MSCs, since osmo-bsc cannot know"
	      " the MSC's chosen CallID. This is enabled by default for A/SCCPlite connections,"
	      " disabled by default for all others.\n"
	      "Send 'X-Osmo-IGN: C' to ignore CallID mismatches. See OsmoMGW.\n")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	msc->x_osmo_ign |= MGCP_X_OSMO_IGN_CALLID;
	msc->x_osmo_ign_configured = true;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(cfg_msc_no_mgw_x_osmo_ign,
	      cfg_msc_no_mgw_x_osmo_ign_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "no mgw x-osmo-ign",
	      NO_STR
	      MGCP_CLIENT_MGW_STR
	      "Do not send X-Osmo-IGN MGCP header to this MSC\n")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	msc->x_osmo_ign = 0;
	msc->x_osmo_ign_configured = true;
	return CMD_SUCCESS;
}

#define OSMUX_STR "RTP multiplexing\n"
DEFUN_USRATTR(cfg_msc_osmux,
	      cfg_msc_osmux_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "osmux (on|off|only)",
	      OSMUX_STR "Enable OSMUX\n" "Disable OSMUX\n" "Only use OSMUX\n")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	if (strcmp(argv[0], "off") == 0)
		msc->use_osmux = OSMUX_USAGE_OFF;
	else if (strcmp(argv[0], "on") == 0)
		msc->use_osmux = OSMUX_USAGE_ON;
	else if (strcmp(argv[0], "only") == 0)
		msc->use_osmux = OSMUX_USAGE_ONLY;

	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(deprecated_ussd_text,
      cfg_net_bsc_mid_call_text_cmd,
      "mid-call-text .TEXT",
      LEGACY_STR LEGACY_STR);

DEFUN_ATTR(cfg_net_bsc_mid_call_timeout,
	   cfg_net_bsc_mid_call_timeout_cmd,
	   "mid-call-timeout NR",
	   "Switch from Grace to Off in NR seconds.\n" "Timeout in seconds\n",
	   CMD_ATTR_IMMEDIATE)
{
	bsc_gsmnet->mid_call_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_rf_socket,
      cfg_net_rf_socket_cmd,
      "bsc-rf-socket PATH",
      "Set the filename for the RF control interface.\n" "RF Control path\n")
{
	osmo_talloc_replace_string(bsc_gsmnet, &bsc_gsmnet->rf_ctrl_name, argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_rf_off_time,
	   cfg_net_rf_off_time_cmd,
	   "bsc-auto-rf-off <1-65000>",
	   "Disable RF on MSC Connection\n" "Timeout\n",
	   CMD_ATTR_IMMEDIATE)
{
	bsc_gsmnet->auto_off_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_net_no_rf_off_time,
	   cfg_net_no_rf_off_time_cmd,
	   "no bsc-auto-rf-off",
	   NO_STR "Disable RF on MSC Connection\n",
	   CMD_ATTR_IMMEDIATE)
{
	bsc_gsmnet->auto_off_timeout = -1;
	return CMD_SUCCESS;
}

DEFUN(show_statistics,
      show_statistics_cmd,
      "show statistics",
      SHOW_STR "Statistics about the BSC\n")
{
	openbsc_vty_print_statistics(vty, bsc_gsmnet);
	return CMD_SUCCESS;
}

DEFUN(show_mscs,
      show_mscs_cmd,
      "show mscs",
      SHOW_STR "MSC Connections and State\n")
{
	struct bsc_msc_data *msc;
	llist_for_each_entry(msc, &bsc_gsmnet->mscs, entry) {
		vty_out(vty, "%d %s %s ",
			msc->a.cs7_instance,
			osmo_ss7_asp_protocol_name(msc->a.asp_proto),
			osmo_sccp_inst_addr_name(msc->a.sccp, &msc->a.bsc_addr));
		vty_out(vty, "%s%s",
			osmo_sccp_inst_addr_name(msc->a.sccp, &msc->a.msc_addr),
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(show_pos,
      show_pos_cmd,
      "show position",
      SHOW_STR "Position information of the BTS\n")
{
	struct gsm_bts *bts;
	struct bts_location *curloc;
	struct tm time;
	char timestr[50];

	llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
		if (llist_empty(&bts->loc_list)) {
			vty_out(vty, "BTS Nr: %d position invalid%s", bts->nr,
				VTY_NEWLINE);
			continue;
		}
		curloc = llist_entry(bts->loc_list.next, struct bts_location, list);
		if (gmtime_r(&curloc->tstamp, &time) == NULL) {
			vty_out(vty, "Time conversion failed for BTS %d%s", bts->nr,
				VTY_NEWLINE);
			continue;
		}
		if (asctime_r(&time, timestr) == NULL) {
			vty_out(vty, "Time conversion failed for BTS %d%s", bts->nr,
				VTY_NEWLINE);
			continue;
		}
		/* Last character in asctime is \n */
		timestr[strlen(timestr)-1] = 0;

		vty_out(vty, "BTS Nr: %d position: %s time: %s%s", bts->nr,
			get_value_string(bts_loc_fix_names, curloc->valid), timestr,
			VTY_NEWLINE);
		vty_out(vty, " lat: %f lon: %f height: %f%s", curloc->lat, curloc->lon,
			curloc->height, VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

DEFUN(gen_position_trap,
      gen_position_trap_cmd,
      "generate-location-state-trap <0-255>",
      "Generate location state report\n"
      "BTS to report\n")
{
	int bts_nr;
	struct gsm_bts *bts;
	struct gsm_network *net = bsc_gsmnet;

	bts_nr = atoi(argv[0]);
	if (bts_nr >= net->num_bts) {
		vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(net, bts_nr);
	bsc_gen_location_state_trap(bts);
	return CMD_SUCCESS;
}

DEFUN(logging_fltr_imsi,
      logging_fltr_imsi_cmd,
      "logging filter imsi IMSI",
	LOGGING_STR FILTER_STR
      "Filter log messages by IMSI\n" "IMSI to be used as filter\n")
{
	struct bsc_subscr *bsc_subscr;
	struct log_target *tgt = osmo_log_vty2tgt(vty);
	const char *imsi = argv[0];

	if (!tgt)
		return CMD_WARNING;

	bsc_subscr = bsc_subscr_find_or_create_by_imsi(bsc_gsmnet->bsc_subscribers, imsi, __func__);

	if (!bsc_subscr) {
		vty_out(vty, "%% failed to enable logging for subscriber with IMSI(%s)%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_filter_bsc_subscr(tgt, bsc_subscr);
	/* log_set_filter has grabbed its own reference  */
	bsc_subscr_put(bsc_subscr, __func__);

	return CMD_SUCCESS;
}

static void dump_one_sub(struct vty *vty, struct bsc_subscr *bsub)
{
	vty_out(vty, " %15s  %08x  %s%s", bsub->imsi, bsub->tmsi, osmo_use_count_to_str_c(OTC_SELECT, &bsub->use_count),
		VTY_NEWLINE);
}

DEFUN(show_subscr_all,
	show_subscr_all_cmd,
	"show subscriber all",
	SHOW_STR "Display information about subscribers\n" "All Subscribers\n")
{
	struct bsc_subscr *bsc_subscr;

	vty_out(vty, " IMSI             TMSI      Use%s", VTY_NEWLINE);
	/*           " 001010123456789  ffffffff  1" */

	llist_for_each_entry(bsc_subscr, bsc_gsmnet->bsc_subscribers, entry)
		dump_one_sub(vty, bsc_subscr);

	return CMD_SUCCESS;
}

DEFUN_DEPRECATED(cfg_net_msc_ping_time, cfg_net_msc_ping_time_cmd,
      "timeout-ping ARG", LEGACY_STR "-\n")
{
	vty_out(vty, "%% timeout-ping / timeout-pong config is deprecated and has no effect%s",
		VTY_NEWLINE);
	return CMD_WARNING;
}

ALIAS_DEPRECATED(cfg_net_msc_ping_time, cfg_net_msc_no_ping_time_cmd,
      "no timeout-ping [ARG]", NO_STR LEGACY_STR "-\n");

ALIAS_DEPRECATED(cfg_net_msc_ping_time, cfg_net_msc_pong_time_cmd,
      "timeout-pong ARG", LEGACY_STR "-\n");

DEFUN_DEPRECATED(cfg_net_msc_dest, cfg_net_msc_dest_cmd,
      "dest A.B.C.D <1-65000> <0-255>", LEGACY_STR "-\n" "-\n" "-\n")
{
	vty_out(vty, "%% dest config is deprecated and has no effect%s", VTY_NEWLINE);
	return CMD_WARNING;
}

ALIAS_DEPRECATED(cfg_net_msc_dest, cfg_net_msc_no_dest_cmd,
      "no dest A.B.C.D <1-65000> <0-255>", NO_STR LEGACY_STR "-\n" "-\n" "-\n");

DEFUN_USRATTR(cfg_net_msc_amr_octet_align,
	      cfg_net_msc_amr_octet_align_cmd,
	      X(BSC_VTY_ATTR_NEW_LCHAN),
	      "amr-payload (octet-aligned|bandwith-efficient",
	      "Set AMR payload framing mode\n"
	      "payload fields aligned on octet boundaries\n"
	      "payload fields packed (AoIP)\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);

	if (strcmp(argv[0], "octet-aligned") == 0)
		data->amr_octet_aligned = true;
	else if (strcmp(argv[0], "bandwith-efficient") == 0)
		data->amr_octet_aligned = false;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_msc_nri_add, cfg_msc_nri_add_cmd,
	   "nri add <0-32767> [<0-32767>]",
	   NRI_STR "Add NRI value or range to the NRI mapping for this MSC\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	struct bsc_msc_data *other_msc;
	bool before;
	int rc;
	const char *message;
	struct osmo_nri_range add_range;

	rc = osmo_nri_ranges_vty_add(&message, &add_range, msc->nri_ranges, argc, argv, bsc_gsmnet->nri_bitlen);
	if (message) {
		NRI_WARN(msc, "%s: " NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	}
	if (rc < 0)
		return CMD_WARNING;

	/* Issue a warning about NRI range overlaps (but still allow them).
	 * Overlapping ranges will map to whichever MSC comes fist in the bsc_gsmnet->mscs llist,
	 * which is not necessarily in the order of increasing msc->nr. */
	before = true;
	llist_for_each_entry(other_msc, &bsc_gsmnet->mscs, entry) {
		if (other_msc == msc) {
			before = false;
			continue;
		}
		if (osmo_nri_range_overlaps_ranges(&add_range, other_msc->nri_ranges)) {
			NRI_WARN(msc, "NRI range [%d..%d] overlaps between msc %d and msc %d."
				 " For overlaps, msc %d has higher priority than msc %d",
				 add_range.first, add_range.last, msc->nr, other_msc->nr,
				 before ? other_msc->nr : msc->nr, before ? msc->nr : other_msc->nr);
		}
	}
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_msc_nri_del, cfg_msc_nri_del_cmd,
	   "nri del <0-32767> [<0-32767>]",
	   NRI_STR "Remove NRI value or range from the NRI mapping for this MSC\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	int rc;
	const char *message;

	rc = osmo_nri_ranges_vty_del(&message, NULL, msc->nri_ranges, argc, argv);
	if (message) {
		NRI_WARN(msc, "%s: " NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	}
	if (rc < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_msc_allow_attach, cfg_msc_allow_attach_cmd,
	   "allow-attach",
	   "Allow this MSC to attach new subscribers (default).\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	msc->allow_attach = true;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_msc_no_allow_attach, cfg_msc_no_allow_attach_cmd,
	   "no allow-attach",
	   NO_STR
	   "Do not assign new subscribers to this MSC."
	   " Useful if an MSC in an MSC pool is configured to off-load subscribers."
	   " The MSC will still be operational for already IMSI-Attached subscribers,"
	   " but the NAS node selection function will skip this MSC for new subscribers\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	msc->allow_attach = false;
	return CMD_SUCCESS;
}

static void msc_write_nri(struct vty *vty, struct bsc_msc_data *msc, bool verbose)
{
	struct osmo_nri_range *r;

	if (verbose) {
		vty_out(vty, "msc %d%s", msc->nr, VTY_NEWLINE);
		if (llist_empty(&msc->nri_ranges->entries)) {
			vty_out(vty, " %% no NRI mappings%s", VTY_NEWLINE);
			return;
		}
	}

	llist_for_each_entry(r, &msc->nri_ranges->entries, entry) {
		if (osmo_nri_range_validate(r, 255))
			vty_out(vty, " %% INVALID RANGE:");
		vty_out(vty, " nri add %d", r->first);
		if (r->first != r->last)
			vty_out(vty, " %d", r->last);
		vty_out(vty, "%s", VTY_NEWLINE);
	}
}

DEFUN(cfg_msc_show_nri, cfg_msc_show_nri_cmd,
      "show nri",
      SHOW_STR NRI_STR)
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);
	msc_write_nri(vty, msc, true);
	return CMD_SUCCESS;
}

DEFUN(show_nri, show_nri_cmd,
      "show nri [" MSC_NR_RANGE "]",
      SHOW_STR NRI_STR "Optional MSC number to limit to\n")
{
	struct bsc_msc_data *msc;
	if (argc > 0) {
		int msc_nr = atoi(argv[0]);
		msc = osmo_msc_data_find(bsc_gsmnet, msc_nr);
		if (!msc) {
			vty_out(vty, "%% No such MSC%s", VTY_NEWLINE);
			return CMD_SUCCESS;
		}
		msc_write_nri(vty, msc, true);
		return CMD_SUCCESS;
	}

	llist_for_each_entry(msc, &bsc_gsmnet->mscs, entry) {
		msc_write_nri(vty, msc, true);
	}
	return CMD_SUCCESS;
}

/* Hidden since it exists only for use by ttcn3 tests */
DEFUN_HIDDEN(mscpool_roundrobin_next, mscpool_roundrobin_next_cmd,
	     "mscpool roundrobin next " MSC_NR_RANGE,
	     "MSC pooling: load balancing across multiple MSCs.\n"
	     "Adjust current state of the MSC round-robin algorithm (for testing).\n"
	     "Set the MSC nr to direct the next new subscriber to (for testing).\n"
	     "MSC number, as in the config file; if the number does not exist,"
	     " the round-robin continues to the next valid number.\n")
{
	bsc_gsmnet->mscs_round_robin_next_nr = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(set_ho_count,
      set_ho_count_cmd,
      "ho_count <0-255>",
	  "Set need handover count\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	if (argc == 1) {
		net->ho_count = atoi(argv[0]);
		return CMD_SUCCESS;
	}
	return CMD_WARNING;
}

int bsc_vty_init(struct gsm_network *network)
{
	cfg_ts_pchan_cmd.string =
		vty_cmd_string_from_valstr(tall_bsc_ctx,
					   gsm_pchant_names,
					   "phys_chan_config (", "|", ")",
					   VTY_DO_LOWER);
	cfg_ts_pchan_cmd.doc =
		vty_cmd_string_from_valstr(tall_bsc_ctx,
					   gsm_pchant_descs,
					   "Physical Channel Combination\n",
					   "\n", "", 0);

	cfg_bts_type_cmd.string =
		vty_cmd_string_from_valstr(tall_bsc_ctx,
					   bts_type_names,
					   "type (", "|", ")",
					   VTY_DO_LOWER);
	cfg_bts_type_cmd.doc =
		vty_cmd_string_from_valstr(tall_bsc_ctx,
					   bts_type_descs,
					   "BTS Vendor/Type\n",
					   "\n", "", 0);

	OSMO_ASSERT(vty_global_gsm_network == NULL);
	vty_global_gsm_network = network;

	osmo_stats_vty_add_cmds();

	install_element(CONFIG_NODE, &cfg_net_cmd);
	install_node(&net_node, config_write_net);
	install_element(GSMNET_NODE, &cfg_net_ncc_cmd);
	install_element(GSMNET_NODE, &cfg_net_mnc_cmd);
	install_element(GSMNET_NODE, &cfg_net_encryption_cmd);
	install_element(GSMNET_NODE, &cfg_net_timezone_cmd);
	install_element(GSMNET_NODE, &cfg_net_timezone_dst_cmd);
	install_element(GSMNET_NODE, &cfg_net_no_timezone_cmd);
	install_element(GSMNET_NODE, &cfg_net_per_loc_upd_cmd);
	install_element(GSMNET_NODE, &cfg_net_no_per_loc_upd_cmd);
	install_element(GSMNET_NODE, &cfg_net_dyn_ts_allow_tch_f_cmd);
	install_element(GSMNET_NODE, &cfg_net_meas_feed_dest_cmd);
	install_element(GSMNET_NODE, &cfg_net_meas_feed_scenario_cmd);
	install_element(GSMNET_NODE, &cfg_net_timer_cmd);
	install_element(GSMNET_NODE, &cfg_net_allow_unusable_timeslots_cmd);

	/* Timer configuration commands (generic osmo_tdef API) */
	osmo_tdef_vty_groups_init(GSMNET_NODE, bsc_tdef_group);

	install_element_ve(&bsc_show_net_cmd);
	install_element_ve(&show_bts_cmd);
	install_element_ve(&show_bts_fail_rep_cmd);
	install_element_ve(&show_rejected_bts_cmd);
	install_element_ve(&show_trx_cmd);
	install_element_ve(&show_trx_con_cmd);
	install_element_ve(&show_ts_cmd);
	install_element_ve(&show_lchan_cmd);
	install_element_ve(&show_lchan_summary_cmd);
	install_element_ve(&show_lchan_summary_all_cmd);
	install_element_ve(&show_timer_cmd);

	install_element_ve(&show_subscr_conn_cmd);

	install_element_ve(&show_paging_cmd);
	install_element_ve(&show_paging_group_cmd);

	install_element(ENABLE_NODE, &handover_any_cmd);
	install_element(ENABLE_NODE, &assignment_any_cmd);
	install_element(ENABLE_NODE, &handover_any_to_arfcn_bsic_cmd);
	/* See also handover commands added on net level from handover_vty.c */

	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();

	install_element(GSMNET_NODE, &cfg_net_neci_cmd);
	install_element(GSMNET_NODE, &cfg_net_dtx_cmd);
	install_element(GSMNET_NODE, &cfg_net_pag_any_tch_cmd);
	install_element(GSMNET_NODE, &cfg_net_nri_bitlen_cmd);
	install_element(GSMNET_NODE, &cfg_net_nri_null_add_cmd);
	install_element(GSMNET_NODE, &cfg_net_nri_null_del_cmd);

	install_element(GSMNET_NODE, &cfg_bts_cmd);
	install_node(&bts_node, config_write_bts);
	install_element(BTS_NODE, &cfg_bts_type_cmd);
	install_element(BTS_NODE, &cfg_description_cmd);
	install_element(BTS_NODE, &cfg_no_description_cmd);
	install_element(BTS_NODE, &cfg_bts_band_cmd);
	install_element(BTS_NODE, &cfg_bts_ci_cmd);
	install_element(BTS_NODE, &cfg_bts_dtxu_cmd);
	install_element(BTS_NODE, &cfg_bts_dtxd_cmd);
	install_element(BTS_NODE, &cfg_bts_no_dtxu_cmd);
	install_element(BTS_NODE, &cfg_bts_no_dtxd_cmd);
	install_element(BTS_NODE, &cfg_bts_lac_cmd);
	install_element(BTS_NODE, &cfg_bts_tsc_cmd);
	install_element(BTS_NODE, &cfg_bts_bsic_cmd);
	install_element(BTS_NODE, &cfg_bts_unit_id_cmd);
	install_element(BTS_NODE, &cfg_bts_deprecated_unit_id_cmd);
	install_element(BTS_NODE, &cfg_bts_rsl_ip_cmd);
	install_element(BTS_NODE, &cfg_bts_deprecated_rsl_ip_cmd);
	install_element(BTS_NODE, &cfg_bts_nokia_site_skip_reset_cmd);
	install_element(BTS_NODE, &cfg_bts_nokia_site_no_loc_rel_cnf_cmd);
	install_element(BTS_NODE, &cfg_bts_nokia_site_bts_reset_timer_cnf_cmd);
	install_element(BTS_NODE, &cfg_bts_stream_id_cmd);
	install_element(BTS_NODE, &cfg_bts_deprecated_stream_id_cmd);
	install_element(BTS_NODE, &cfg_bts_oml_e1_cmd);
	install_element(BTS_NODE, &cfg_bts_oml_e1_tei_cmd);
	install_element(BTS_NODE, &cfg_bts_challoc_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_tx_integer_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_max_trans_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_desc_att_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_dscr_att_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_desc_bs_pa_mfrms_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_dscr_bs_pa_mfrms_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_desc_bs_ag_blks_res_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_dscr_bs_ag_blks_res_cmd);
	install_element(BTS_NODE, &cfg_bts_ccch_load_ind_thresh_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_nm_b_thresh_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_nm_ldavg_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_barred_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_ec_allowed_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_ac_class_cmd);
	install_element(BTS_NODE, &cfg_bts_ms_max_power_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_resel_hyst_cmd);
	install_element(BTS_NODE, &cfg_bts_rxlev_acc_min_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_bar_qualify_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_resel_ofs_cmd);
	install_element(BTS_NODE, &cfg_bts_temp_ofs_cmd);
	install_element(BTS_NODE, &cfg_bts_temp_ofs_inf_cmd);
	install_element(BTS_NODE, &cfg_bts_penalty_time_cmd);
	install_element(BTS_NODE, &cfg_bts_penalty_time_rsvd_cmd);
	install_element(BTS_NODE, &cfg_bts_radio_link_timeout_cmd);
	install_element(BTS_NODE, &cfg_bts_radio_link_timeout_inf_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_11bit_rach_support_for_egprs_cmd);
	install_element(BTS_NODE, &cfg_bts_no_gprs_egprs_pkt_chan_req_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_egprs_pkt_chan_req_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_ns_timer_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_rac_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_net_ctrl_ord_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_ctrl_ack_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_ccn_active_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_pwr_ctrl_alpha_cmd);
	install_element(BTS_NODE, &cfg_no_bts_gprs_ctrl_ack_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_bvci_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_cell_timer_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsei_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvci_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvc_lport_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvc_rport_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvc_rip_cmd);
	install_element(BTS_NODE, &cfg_bts_pag_free_cmd);
	install_element(BTS_NODE, &cfg_bts_si_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_si_static_cmd);
	install_element(BTS_NODE, &cfg_bts_si_unused_send_empty_cmd);
	install_element(BTS_NODE, &cfg_bts_no_si_unused_send_empty_cmd);
	install_element(BTS_NODE, &cfg_bts_early_cm_cmd);
	install_element(BTS_NODE, &cfg_bts_early_cm_3g_cmd);
	install_element(BTS_NODE, &cfg_bts_neigh_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_neigh_cmd);
	install_element(BTS_NODE, &cfg_bts_si5_neigh_cmd);
	install_element(BTS_NODE, &cfg_bts_si2quater_neigh_add_cmd);
	install_element(BTS_NODE, &cfg_bts_si2quater_neigh_del_cmd);
	install_element(BTS_NODE, &cfg_bts_si2quater_uarfcn_add_cmd);
	install_element(BTS_NODE, &cfg_bts_si2quater_uarfcn_del_cmd);
	install_element(BTS_NODE, &cfg_bts_excl_rf_lock_cmd);
	install_element(BTS_NODE, &cfg_bts_no_excl_rf_lock_cmd);
	install_element(BTS_NODE, &cfg_bts_force_comb_si_cmd);
	install_element(BTS_NODE, &cfg_bts_no_force_comb_si_cmd);
	install_element(BTS_NODE, &cfg_bts_codec0_cmd);
	install_element(BTS_NODE, &cfg_bts_codec1_cmd);
	install_element(BTS_NODE, &cfg_bts_codec2_cmd);
	install_element(BTS_NODE, &cfg_bts_codec3_cmd);
	install_element(BTS_NODE, &cfg_bts_codec4_cmd);
	install_element(BTS_NODE, &cfg_bts_depends_on_cmd);
	install_element(BTS_NODE, &cfg_bts_no_depends_on_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_modes1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_modes2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_modes3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_modes4_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_thres1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_thres2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_thres3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_hyst1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_hyst2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_hyst3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_start_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_modes1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_modes2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_modes3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_modes4_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_thres1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_thres2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_thres3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_hyst1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_hyst2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_hyst3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_start_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_pcu_sock_cmd);
	install_element(BTS_NODE, &cfg_bts_acc_rotate_cmd);
	install_element(BTS_NODE, &cfg_bts_acc_rotate_quantum_cmd);
	install_element(BTS_NODE, &cfg_bts_acc_ramping_cmd);
	install_element(BTS_NODE, &cfg_bts_no_acc_ramping_cmd);
	install_element(BTS_NODE, &cfg_bts_acc_ramping_step_interval_cmd);
	install_element(BTS_NODE, &cfg_bts_acc_ramping_step_size_cmd);
	install_element(BTS_NODE, &cfg_bts_acc_ramping_chan_load_cmd);
	install_element(BTS_NODE, &cfg_bts_t3113_dynamic_cmd);
	install_element(BTS_NODE, &cfg_bts_no_t3113_dynamic_cmd);
	install_element(BTS_NODE, &cfg_bts_rep_dl_facch_cmd);
	install_element(BTS_NODE, &cfg_bts_rep_no_dl_facch_cmd);
	install_element(BTS_NODE, &cfg_bts_rep_ul_dl_sacch_cmd);
	install_element(BTS_NODE, &cfg_bts_rep_no_ul_dl_sacch_cmd);
	install_element(BTS_NODE, &cfg_bts_rep_rxqual_cmd);

	neighbor_ident_vty_init(network, network->neighbor_bss_cells);
	/* See also handover commands added on bts level from handover_vty.c */

	install_element(BTS_NODE, &cfg_bts_power_ctrl_cmd);
	install_element(BTS_NODE, &cfg_bts_no_power_ctrl_cmd);
	install_node(&power_ctrl_node, dummy_config_write);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_mode_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_bs_power_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_ctrl_interval_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_step_size_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_rxlev_thresh_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_rxqual_thresh_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_rxlev_thresh_comp_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_rxqual_thresh_comp_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_no_avg_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_avg_params_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_avg_algo_cmd);
	install_element(POWER_CTRL_NODE, &cfg_power_ctrl_avg_osmo_ewma_cmd);

	install_element(BTS_NODE, &cfg_trx_cmd);
	install_node(&trx_node, dummy_config_write);
	install_element(TRX_NODE, &cfg_trx_arfcn_cmd);
	install_element(TRX_NODE, &cfg_description_cmd);
	install_element(TRX_NODE, &cfg_no_description_cmd);
	install_element(TRX_NODE, &cfg_trx_nominal_power_cmd);
	install_element(TRX_NODE, &cfg_trx_max_power_red_cmd);
	install_element(TRX_NODE, &cfg_trx_rsl_e1_cmd);
	install_element(TRX_NODE, &cfg_trx_rsl_e1_tei_cmd);
	install_element(TRX_NODE, &cfg_trx_rf_locked_cmd);

	install_element(TRX_NODE, &cfg_ts_cmd);
	install_node(&ts_node, dummy_config_write);
	install_element(TS_NODE, &cfg_ts_pchan_cmd);
	install_element(TS_NODE, &cfg_ts_pchan_compat_cmd);
	install_element(TS_NODE, &cfg_ts_tsc_cmd);
	install_element(TS_NODE, &cfg_ts_hopping_cmd);
	install_element(TS_NODE, &cfg_ts_hsn_cmd);
	install_element(TS_NODE, &cfg_ts_maio_cmd);
	install_element(TS_NODE, &cfg_ts_arfcn_add_cmd);
	install_element(TS_NODE, &cfg_ts_arfcn_del_cmd);
	install_element(TS_NODE, &cfg_ts_arfcn_del_all_cmd);
	install_element(TS_NODE, &cfg_ts_e1_subslot_cmd);

	install_element(ENABLE_NODE, &drop_bts_cmd);
	install_element(ENABLE_NODE, &restart_bts_cmd);
	install_element(ENABLE_NODE, &bts_resend_sysinfo_cmd);
	install_element(ENABLE_NODE, &bts_resend_power_ctrl_params_cmd);
	install_element(ENABLE_NODE, &pdch_act_cmd);
	install_element(ENABLE_NODE, &lchan_act_cmd);
	install_element(ENABLE_NODE, &lchan_act_all_cmd);
	install_element(ENABLE_NODE, &lchan_act_all_bts_cmd);
	install_element(ENABLE_NODE, &lchan_act_all_trx_cmd);
	install_element(ENABLE_NODE, &lchan_mdcx_cmd);
	install_element(ENABLE_NODE, &lchan_set_borken_cmd);

	install_element(ENABLE_NODE, &handover_subscr_conn_cmd);
	install_element(ENABLE_NODE, &assignment_subscr_conn_cmd);
	install_element(ENABLE_NODE, &smscb_cmd_cmd);
	install_element(ENABLE_NODE, &ctrl_trap_cmd);

	abis_nm_vty_init();
	abis_om2k_vty_init();
	e1inp_vty_init();
	osmo_fsm_vty_add_cmds();

	ho_vty_init();
	cbc_vty_init();
	smscb_vty_init();

	install_element(CONFIG_NODE, &cfg_net_msc_cmd);
	install_element(CONFIG_NODE, &cfg_net_bsc_cmd);

	install_node(&bsc_node, config_write_bsc);
	install_element(BSC_NODE, &cfg_net_bsc_mid_call_text_cmd);
	install_element(BSC_NODE, &cfg_net_bsc_mid_call_timeout_cmd);
	install_element(BSC_NODE, &cfg_net_rf_socket_cmd);
	install_element(BSC_NODE, &cfg_net_rf_off_time_cmd);
	install_element(BSC_NODE, &cfg_net_no_rf_off_time_cmd);
	install_element(BSC_NODE, &cfg_net_bsc_missing_msc_ussd_cmd);
	install_element(BSC_NODE, &cfg_net_bsc_no_missing_msc_text_cmd);

	install_node(&msc_node, config_write_msc);
	install_element(MSC_NODE, &cfg_net_bsc_ncc_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_mcc_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_lac_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_ci_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_rtp_base_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_codec_list_cmd);
	install_element(MSC_NODE, &cfg_net_msc_dest_cmd);
	install_element(MSC_NODE, &cfg_net_msc_no_dest_cmd);
	install_element(MSC_NODE, &cfg_net_msc_welcome_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_no_welcome_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_lost_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_no_lost_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_grace_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_no_grace_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_type_cmd);
	install_element(MSC_NODE, &cfg_net_msc_emerg_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_12_2_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_10_2_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_7_95_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_7_40_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_6_70_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_5_90_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_5_15_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_4_75_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_octet_align_cmd);
	install_element(MSC_NODE, &cfg_net_msc_lcls_mode_cmd);
	install_element(MSC_NODE, &cfg_net_msc_lcls_mismtch_cmd);
	install_element(MSC_NODE, &cfg_msc_cs7_bsc_addr_cmd);
	install_element(MSC_NODE, &cfg_msc_cs7_msc_addr_cmd);
	install_element(MSC_NODE, &cfg_msc_cs7_asp_proto_cmd);
	install_element(MSC_NODE, &cfg_msc_nri_add_cmd);
	install_element(MSC_NODE, &cfg_msc_nri_del_cmd);
	install_element(MSC_NODE, &cfg_msc_show_nri_cmd);
	install_element(MSC_NODE, &cfg_msc_allow_attach_cmd);
	install_element(MSC_NODE, &cfg_msc_no_allow_attach_cmd);

	/* Deprecated: ping time config, kept to support legacy config files. */
	install_element(MSC_NODE, &cfg_net_msc_no_ping_time_cmd);
	install_element(MSC_NODE, &cfg_net_msc_ping_time_cmd);
	install_element(MSC_NODE, &cfg_net_msc_pong_time_cmd);

	install_element_ve(&show_statistics_cmd);
	install_element_ve(&show_mscs_cmd);
	install_element_ve(&show_pos_cmd);
	install_element_ve(&logging_fltr_imsi_cmd);
	install_element_ve(&show_subscr_all_cmd);
	install_element_ve(&show_nri_cmd);

	install_element(ENABLE_NODE, &gen_position_trap_cmd);
	install_element(ENABLE_NODE, &mscpool_roundrobin_next_cmd);

	install_element(CFG_LOG_NODE, &logging_fltr_imsi_cmd);

	mgcp_client_vty_init(network, MSC_NODE, network->mgw.conf);
	install_element(MSC_NODE, &cfg_msc_mgw_x_osmo_ign_cmd);
	install_element(MSC_NODE, &cfg_msc_no_mgw_x_osmo_ign_cmd);
	install_element(MSC_NODE, &cfg_msc_osmux_cmd);

	install_element_ve(&set_ho_count_cmd);

	return 0;
}
