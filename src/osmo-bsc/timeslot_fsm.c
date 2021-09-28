/* osmo-bsc API to manage timeslot status: init and switch of dynamic PDCH.
 *
 * (C) 2017 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
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

#include <osmocom/core/logging.h>

#include <osmocom/bsc/debug.h>

#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/pcu_if.h>
#include <osmocom/bsc/bts.h>

static struct osmo_fsm ts_fsm;

#define CHAN_ACT_DEACT_TIMEOUT 4 /* TODO: proper T number? */

enum ts_fsm_T {
	T_CHAN_ACT_DEACT=23001,
};

struct gsm_bts_trx_ts *ts_fi_ts(struct osmo_fsm_inst *fi)
{
	OSMO_ASSERT(fi);
	OSMO_ASSERT(fi->fsm == &ts_fsm);
	OSMO_ASSERT(fi->priv);
	return fi->priv;
}

static void ts_fsm_update_id(struct gsm_bts_trx_ts *ts)
{
	osmo_fsm_inst_update_id_f(ts->fi, "%u-%u-%u-%s", ts->trx->bts->nr, ts->trx->nr, ts->nr,
				  gsm_pchan_id(ts->pchan_on_init));
}

void ts_fsm_init()
{
	OSMO_ASSERT(osmo_fsm_register(&ts_fsm) == 0);
}

void ts_fsm_alloc(struct gsm_bts_trx_ts *ts)
{
	OSMO_ASSERT(!ts->fi);
	OSMO_ASSERT(ts->trx);
	ts->fi = osmo_fsm_inst_alloc(&ts_fsm, ts->trx, ts, LOGL_DEBUG, NULL);
	OSMO_ASSERT(ts->fi);
	ts_fsm_update_id(ts);
}

enum lchan_sanity {
	LCHAN_IS_INSANE = -1,
	LCHAN_IS_READY_TO_GO,
	LCHAN_NEEDS_PCHAN_CHANGE,
};

static enum lchan_sanity is_lchan_sane(struct gsm_bts_trx_ts *ts, struct gsm_lchan *lchan)
{
	OSMO_ASSERT(ts);
	OSMO_ASSERT(lchan);
	if (lchan->ts != ts)
		return LCHAN_IS_INSANE;
	if (!lchan->fi)
		return LCHAN_IS_INSANE;

	if (lchan->type == gsm_lchan_type_by_pchan(ts->pchan_is))
		return LCHAN_IS_READY_TO_GO;

	switch (ts->pchan_on_init) {
	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
		if (lchan->type == GSM_LCHAN_TCH_H)
			return LCHAN_NEEDS_PCHAN_CHANGE;
		/* fall thru */
	case GSM_PCHAN_TCH_F_PDCH:
		if (lchan->type == GSM_LCHAN_TCH_F)
			return LCHAN_NEEDS_PCHAN_CHANGE;
		/* fall thru */
	default:
		return LCHAN_IS_INSANE;
	}

}

static void lchan_dispatch(struct gsm_lchan *lchan, uint32_t lchan_ev)
{
	if (!lchan->fi)
		return;
	osmo_fsm_inst_dispatch(lchan->fi, lchan_ev, NULL);
	OSMO_ASSERT(lchan->fi->state != LCHAN_ST_WAIT_TS_READY);
}

static int ts_count_active_lchans(struct gsm_bts_trx_ts *ts)
{
	struct gsm_lchan *lchan;
	int count = 0;

	ts_for_each_lchan(lchan, ts) {
		if (lchan->fi->state == LCHAN_ST_UNUSED)
			continue;
		count++;
	}

	return count;
}

static void ts_lchans_dispatch(struct gsm_bts_trx_ts *ts, int lchan_state, uint32_t lchan_ev)
{
	struct gsm_lchan *lchan;

	ts_for_each_potential_lchan(lchan, ts) {
		if (lchan_state >= 0
		    && !lchan_state_is(lchan, lchan_state))
			continue;
		lchan_dispatch(lchan, lchan_ev);
	}
}

static void ts_terminate_lchan_fsms(struct gsm_bts_trx_ts *ts)
{
	struct gsm_lchan *lchan;

	ts_for_each_potential_lchan(lchan, ts) {
		osmo_fsm_inst_term(lchan->fi, OSMO_FSM_TERM_REQUEST, NULL);
	}
}

static int ts_lchans_waiting(struct gsm_bts_trx_ts *ts)
{
	struct gsm_lchan *lchan;
	int count = 0;
	ts_for_each_potential_lchan(lchan, ts)
		if (lchan->fi->state == LCHAN_ST_WAIT_TS_READY)
			count++;
	return count;
}

static void ts_fsm_error(struct osmo_fsm_inst *fi, uint32_t state_chg, const char *fmt, ...)
{
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);

	char *errmsg = NULL;

	if (fmt) {
		va_list ap;

		va_start(ap, fmt);
		errmsg = talloc_vasprintf(ts->trx, fmt, ap);
		va_end(ap);
	}

	if (ts->last_errmsg)
		talloc_free(ts->last_errmsg);
	ts->last_errmsg = errmsg;

	if (errmsg)
		LOG_TS(ts, LOGL_ERROR, "%s\n", errmsg);

	ts_lchans_dispatch(ts, LCHAN_ST_WAIT_TS_READY, LCHAN_EV_TS_ERROR);
	if (fi->state != state_chg)
		osmo_fsm_inst_state_chg(fi, state_chg, 0, 0);
}

static void ts_fsm_err_ready_to_go_in_pdch(struct osmo_fsm_inst *fi, struct gsm_lchan *lchan)
{
	/* This shouldn't ever happen, so aggressively mark it. */
	ts_fsm_error(fi, TS_ST_BORKEN,
		     "Internal error: lchan marked as 'ready to go', but activating"
		     " any lchan should need PCHAN switchover in state %s (lchan: %s)",
		     osmo_fsm_inst_state_name(fi), gsm_lchan_name(lchan));
}

void ts_setup_lchans(struct gsm_bts_trx_ts *ts)
{
	int i, max_lchans;

	ts->pchan_on_init = ts->pchan_from_config;
	ts_fsm_update_id(ts);

	max_lchans = pchan_subslots(ts->pchan_on_init);
	LOG_TS(ts, LOGL_DEBUG, "max lchans: %d\n", max_lchans);

	for (i = 0; i < max_lchans; i++) {
		/* If we receive more than one Channel OPSTART ACK, don't fail on the second init. */
		if (ts->lchan[i].fi)
			continue;
		lchan_fsm_alloc(&ts->lchan[i]);
	}

	switch (ts->pchan_on_init) {
	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
		ts->pchan_is = GSM_PCHAN_NONE;
		break;
	case GSM_PCHAN_TCH_F_PDCH:
		ts->pchan_is = GSM_PCHAN_TCH_F;
		break;
	default:
		ts->pchan_is = ts->pchan_on_init;
		break;
	}

	LOG_TS(ts, LOGL_DEBUG, "lchans initialized: %d\n", max_lchans);
}

static void ts_fsm_not_initialized(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);
	switch (event) {

	case TS_EV_OML_READY:
		ts->pdch_act_allowed = true;
		ts->is_oml_ready = true;
		ts_setup_lchans(ts);
		if (!ts->is_rsl_ready) {
			LOG_TS(ts, LOGL_DEBUG, "No RSL link yet\n");
			return;
		}
		/* -> UNUSED below */
		break;

	case TS_EV_RSL_READY:
		ts->pdch_act_allowed = true;
		ts->is_rsl_ready = true;
		if (!ts->is_oml_ready) {
			LOG_TS(ts, LOGL_DEBUG, "OML not ready yet\n");
			return;
		}
		/* -> UNUSED below */
		break;

	case TS_EV_LCHAN_REQUESTED:
		{
			/* TS is not initialized, no lchan can be requested. */
			struct gsm_lchan *lchan = data;
			if (lchan && lchan->fi)
				osmo_fsm_inst_dispatch(fi, LCHAN_EV_TS_ERROR, NULL);
		}
		return;

	case TS_EV_LCHAN_UNUSED:
		/* ignored. */
		return;

	default:
		OSMO_ASSERT(false);
	}

	osmo_fsm_inst_state_chg(fi, TS_ST_UNUSED, 0, 0);
}

static void ts_fsm_unused_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);
	struct gsm_bts *bts = ts->trx->bts;

	/* We are entering the unused state. There must by definition not be any lchans waiting to be
	 * activated. */
	if (ts_lchans_waiting(ts)) {
		ts_fsm_error(fi, TS_ST_BORKEN,
			     "Internal error: entering UNUSED state, but there are lchans waiting to be"
			     " activated. Not activating them to prevent infinite loops.");
		return;
	}

	switch (ts->pchan_on_init) {
	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
	case GSM_PCHAN_TCH_F_PDCH:
		if (bts->gprs.mode == BTS_GPRS_NONE) {
			LOG_TS(ts, LOGL_DEBUG, "GPRS mode is 'none': not activating PDCH.\n");
			return;
		}
		if (!ts->pdch_act_allowed) {
			LOG_TS(ts, LOGL_DEBUG, "PDCH is disabled for this timeslot,"
			       " either due to a PDCH ACT NACK, or from manual VTY command:"
			       " not activating PDCH. (last error: %s)\n",
			       ts->last_errmsg ? : "-");
			return;
		}
		osmo_fsm_inst_state_chg(fi, TS_ST_WAIT_PDCH_ACT, CHAN_ACT_DEACT_TIMEOUT,
					T_CHAN_ACT_DEACT);
		break;

	case GSM_PCHAN_CCCH_SDCCH4_CBCH:
	case GSM_PCHAN_SDCCH8_SACCH8C_CBCH:
		/* For any pchans containing a CBCH, lchan[2] is reserved for CBCH and cannot be
		 * allocated for SDCCH. */
		OSMO_ASSERT(ts->lchan[2].fi);
		ts->lchan[2].type = GSM_LCHAN_CBCH;
		osmo_fsm_inst_state_chg(ts->lchan[2].fi, LCHAN_ST_CBCH, 0, 0);
		break;

	default:
		/* nothing to do */
		break;
	}
}

static void ts_fsm_unused(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);

	switch (event) {

	case TS_EV_LCHAN_REQUESTED:
		{
			struct gsm_lchan *lchan = data;
			switch (is_lchan_sane(ts, lchan)) {
			case LCHAN_NEEDS_PCHAN_CHANGE:
				/* Osmocom style dyn TS: in UNUSED state, PDCH is already switched off,
				 * we merely need to RSL Chan Activ the new lchan. For ip.access style
				 * dyn TS this is already TCH/F, and we should never hit this. */
			case LCHAN_IS_READY_TO_GO:
				osmo_fsm_inst_state_chg(fi, TS_ST_IN_USE, 0, 0);
				return;
			default:
				osmo_fsm_inst_dispatch(lchan->fi, LCHAN_EV_TS_ERROR, NULL);
				return;
			}
		}

	case TS_EV_LCHAN_UNUSED:
		/* ignored. */
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static inline void ts_fsm_pdch_deact(struct osmo_fsm_inst *fi)
{
	osmo_fsm_inst_state_chg(fi, TS_ST_WAIT_PDCH_DEACT, CHAN_ACT_DEACT_TIMEOUT, T_CHAN_ACT_DEACT);
}

static void ts_fsm_wait_pdch_act_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int rc;
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);

	rc = rsl_tx_dyn_ts_pdch_act_deact(ts, true);

	/* On error, we couldn't send the activation message. If we can't send messages, we're broken.
	 * (Also avoiding a recursion loop: enter UNUSED, try to PDCH act, fail, enter UNUSED, try to
	 * PDCH act,...). */
	if (rc)
		ts_fsm_error(fi, TS_ST_BORKEN, "Unable to send PDCH activation");
}

static void ts_fsm_wait_pdch_act(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);
	struct rate_ctr_group *bts_ctrs = ts->trx->bts->bts_ctrs;
	switch (event) {

	case TS_EV_PDCH_ACT_ACK:
		osmo_fsm_inst_state_chg(fi, TS_ST_PDCH, 0, 0);
		return;

	case TS_EV_PDCH_ACT_NACK:
		if (ts->pchan_on_init == GSM_PCHAN_TCH_F_PDCH)
			rate_ctr_inc(&bts_ctrs->ctr[BTS_CTR_RSL_IPA_NACK]);
		else
			rate_ctr_inc(&bts_ctrs->ctr[BTS_CTR_CHAN_ACT_NACK]);
		ts->pdch_act_allowed = false;
		ts_fsm_error(fi, TS_ST_UNUSED, "Received PDCH activation NACK");
		return;

	case TS_EV_LCHAN_REQUESTED:
		{
			struct gsm_lchan *lchan = data;
			switch (is_lchan_sane(ts, lchan)) {
			case LCHAN_IS_READY_TO_GO:
				/* PDCH activation has not been acked, the previous pchan kind may still
				 * linger in ts->pchan and make it look like the ts is usable right away.
				 * But we've started the switchover and must finish that first. */
			case LCHAN_NEEDS_PCHAN_CHANGE:
				/* PDCH onenter will see that the lchan is waiting and continue to switch
				 * off PDCH right away. */
				return;

			default:
				lchan_dispatch(lchan, LCHAN_EV_TS_ERROR);
				return;
			}
		}

	case TS_EV_LCHAN_UNUSED:
		/* ignored. */
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void ts_fsm_pdch_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int count;
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);

	/* Set pchan = PDCH status, but double check. */
	switch (ts->pchan_on_init) {
	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
	case GSM_PCHAN_TCH_F_PDCH:
	case GSM_PCHAN_PDCH:
		ts->pchan_is = GSM_PCHAN_PDCH;
		break;
	default:
		ts_fsm_error(fi, TS_ST_BORKEN, "pchan %s is incapable of activating PDCH",
			     gsm_pchan_name(ts->pchan_on_init));
		return;
	}

	/* PDCH use has changed, tell the PCU about it. */
	pcu_info_update(ts->trx->bts);

	/* If we received TS_EV_LCHAN_REQUESTED in the meantime, go right out of PDCH again. */
	if ((count = ts_lchans_waiting(ts))) {
		LOG_TS(ts, LOGL_DEBUG, "%d lchan(s) waiting for usable timeslot\n", count);
		ts_fsm_pdch_deact(fi);
	}
}

static void ts_fsm_pdch(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);
	switch (event) {

	case TS_EV_LCHAN_REQUESTED:
		{
			struct gsm_lchan *lchan = data;
			switch (is_lchan_sane(ts, lchan)) {
			case LCHAN_NEEDS_PCHAN_CHANGE:
				ts_fsm_pdch_deact(fi);
				return;

			case LCHAN_IS_READY_TO_GO:
				ts_fsm_err_ready_to_go_in_pdch(fi, lchan);
				return;

			default:
				/* Reject just this lchan. */
				lchan_dispatch(lchan, LCHAN_EV_TS_ERROR);
				return;
			}
		}

	case TS_EV_LCHAN_UNUSED:
		/* ignored */
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void ts_fsm_wait_pdch_deact_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	int rc;
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);

	rc = rsl_tx_dyn_ts_pdch_act_deact(ts, false);

	/* On error, we couldn't send the deactivation message. If we can't send messages, we're broken.
	 */
	if (rc)
		ts_fsm_error(fi, TS_ST_BORKEN, "Unable to send PDCH deactivation");
}

static void ts_fsm_wait_pdch_deact(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);
	switch (event) {

	case TS_EV_PDCH_DEACT_ACK:
		/* Remove pchan = PDCH status, but double check. */
		switch (ts->pchan_on_init) {
		case GSM_PCHAN_TCH_F_TCH_H_PDCH:
			ts->pchan_is = GSM_PCHAN_NONE;
			break;
		case GSM_PCHAN_TCH_F_PDCH:
			ts->pchan_is = GSM_PCHAN_TCH_F;
			break;
		default:
			ts_fsm_error(fi, TS_ST_BORKEN, "pchan %s is incapable of deactivating PDCH",
				     gsm_pchan_name(ts->pchan_on_init));
			return;
		}
		osmo_fsm_inst_state_chg(fi, TS_ST_IN_USE, 0, 0);
		/* IN_USE onenter will signal all waiting lchans. */

		/* PDCH use has changed, tell the PCU about it. */
		pcu_info_update(ts->trx->bts);
		return;

	case TS_EV_PDCH_DEACT_NACK:
		if (ts->pchan_on_init == GSM_PCHAN_TCH_F_PDCH)
			rate_ctr_inc(&ts->trx->bts->bts_ctrs->ctr[BTS_CTR_RSL_IPA_NACK]);
		/* For Osmocom style dyn TS, there actually is no NACK, since there is no RF Channel
		 * Release NACK message in RSL. */
		ts_fsm_error(fi, TS_ST_BORKEN, "Received PDCH deactivation NACK");
		return;

	case TS_EV_LCHAN_REQUESTED:
		{
			struct gsm_lchan *lchan = data;
			switch (is_lchan_sane(ts, lchan)) {
			case LCHAN_NEEDS_PCHAN_CHANGE:
				/* IN_USE onenter will see that the lchan is waiting and signal it. */
				return;

			case LCHAN_IS_READY_TO_GO:
				ts_fsm_err_ready_to_go_in_pdch(fi, lchan);
				return;

			default:
				/* Reject just this lchan. */
				lchan_dispatch(lchan, LCHAN_EV_TS_ERROR);
				return;
			}
		}

	case TS_EV_LCHAN_UNUSED:
		/* ignored */
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void ts_fsm_in_use_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	bool ok;
	struct gsm_lchan *lchan;
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);
	enum gsm_chan_t activating_type = GSM_LCHAN_NONE;

	/* After being in use, allow PDCH act again, if appropriate. */
	ts->pdch_act_allowed = true;

	/* For static TS, check validity. For dyn TS, figure out which PCHAN this should become. */
	ts_for_each_potential_lchan(lchan, ts) {
		if (lchan_state_is(lchan, LCHAN_ST_UNUSED))
			continue;

		switch (lchan->type) {
		case GSM_LCHAN_TCH_H:
		case GSM_LCHAN_TCH_F:
		case GSM_LCHAN_SDCCH:
			ok = ts_is_capable_of_lchant(ts, lchan->type);
			break;
		default:
			ok = false;
			break;
		}

		if (!ok && lchan_state_is(lchan, LCHAN_ST_WAIT_TS_READY)) {
			LOG_TS(ts, LOGL_ERROR, "lchan activation of %s is not permitted for %s (%s)\n",
			       gsm_lchant_name(lchan->type), gsm_pchan_name(ts->pchan_on_init),
			       gsm_lchan_name(lchan));
			lchan_dispatch(lchan, LCHAN_EV_TS_ERROR);
		}

		if (!ok)
			continue;

		if (activating_type == GSM_LCHAN_NONE)
			activating_type = lchan->type;
		else if (activating_type != lchan->type) {
			LOG_TS(ts, LOGL_ERROR, "lchan type %s mismatches %s (%s)\n",
			       gsm_lchant_name(lchan->type), gsm_lchant_name(activating_type),
			       gsm_lchan_name(lchan));
			lchan_dispatch(lchan, LCHAN_EV_TS_ERROR);
		}
	}

	ok = false;
	switch (activating_type) {
	case GSM_LCHAN_SDCCH:
	case GSM_LCHAN_TCH_F:
	case GSM_LCHAN_TCH_H:
		ok = ts_is_capable_of_lchant(ts, activating_type);
		break;

	case GSM_LCHAN_NONE:
		LOG_TS(ts, LOGL_DEBUG, "Entered IN_USE state but no lchans are actually in use now.\n");
		break;

	default:
		LOG_TS(ts, LOGL_ERROR, "cannot use timeslot as %s\n", gsm_lchant_name(activating_type));
		ts_lchans_dispatch(ts, LCHAN_ST_WAIT_TS_READY, LCHAN_EV_TS_ERROR);
		break;
	}

	if (!ok) {
		osmo_fsm_inst_state_chg(fi, TS_ST_UNUSED, 0, 0);
		return;
	}

	/* Make sure dyn TS pchan_is is updated. For TCH/F_PDCH, there are only PDCH or TCH/F modes, but
	 * for Osmocom style TCH/F_TCH/H_PDCH the pchan_is == NONE until an lchan is activated. */
	if (ts->pchan_on_init == GSM_PCHAN_TCH_F_TCH_H_PDCH)
		ts->pchan_is = gsm_pchan_by_lchan_type(activating_type);
	ts_lchans_dispatch(ts, LCHAN_ST_WAIT_TS_READY, LCHAN_EV_TS_READY);
}

static void ts_fsm_in_use(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);
	switch (event) {
	case TS_EV_LCHAN_UNUSED:
		if (!ts_count_active_lchans(ts))
			osmo_fsm_inst_state_chg(fi, TS_ST_UNUSED, 0, 0);
		return;

	case TS_EV_LCHAN_REQUESTED:
		{
			struct gsm_lchan *lchan = data;
			switch (is_lchan_sane(ts, lchan)) {
			case LCHAN_IS_READY_TO_GO:
				osmo_fsm_inst_dispatch(lchan->fi, LCHAN_EV_TS_READY, NULL);
				return;

			case LCHAN_NEEDS_PCHAN_CHANGE:
				LOG_TS(ts, LOGL_ERROR,
				       "cannot activate lchan of mismatching pchan type"
				       " when the TS is already in use: %s\n",
				       gsm_lchan_name(lchan));
				/* fall thru */
			default:
				/* Reject just this lchan. */
				lchan_dispatch(lchan, LCHAN_EV_TS_ERROR);
				return;
			}
		}

	default:
		OSMO_ASSERT(false);
	}
}

static void ts_fsm_borken_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);
	struct gsm_bts *bts = ts->trx->bts;
	enum bts_counter_id ctr;
	switch (prev_state) {
	case TS_ST_NOT_INITIALIZED:
		ctr = BTS_CTR_TS_BORKEN_FROM_NOT_INITIALIZED;
		break;
	case TS_ST_UNUSED:
		ctr = BTS_CTR_TS_BORKEN_FROM_UNUSED;
		break;
	case TS_ST_WAIT_PDCH_ACT:
		ctr = BTS_CTR_TS_BORKEN_FROM_WAIT_PDCH_ACT;
		break;
	case TS_ST_PDCH:
		ctr = BTS_CTR_TS_BORKEN_FROM_PDCH;
		break;
	case TS_ST_WAIT_PDCH_DEACT:
		ctr = BTS_CTR_TS_BORKEN_FROM_WAIT_PDCH_DEACT;
		break;
	case TS_ST_IN_USE:
		ctr = BTS_CTR_TS_BORKEN_FROM_IN_USE;
		break;
	case TS_ST_BORKEN:
		ctr = BTS_CTR_TS_BORKEN_FROM_BORKEN;
		break;
	default:
		ctr = BTS_CTR_TS_BORKEN_FROM_UNKNOWN;
	}
	rate_ctr_inc(&bts->bts_ctrs->ctr[ctr]);
	osmo_stat_item_inc(bts->bts_statg->items[BTS_STAT_TS_BORKEN], 1);
}

static void ts_fsm_borken(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case TS_EV_LCHAN_UNUSED:
		/* ignored */
		return;

	case TS_EV_LCHAN_REQUESTED:
		{
			struct gsm_lchan *lchan = data;
			lchan_dispatch(lchan, LCHAN_EV_TS_ERROR);
			return;
		}

	case TS_EV_PDCH_ACT_ACK:
	case TS_EV_PDCH_ACT_NACK:
		{
			struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);
			struct gsm_bts *bts = ts->trx->bts;
			/* Late PDCH activation ACK/NACK is not a crime.
			 * Just process them as normal. */
			rate_ctr_inc(&bts->bts_ctrs->ctr[BTS_CTR_TS_BORKEN_EV_PDCH_ACT_ACK_NACK]);
			osmo_stat_item_dec(bts->bts_statg->items[BTS_STAT_TS_BORKEN], 1);
			ts_fsm_wait_pdch_act(fi, event, data);
			return;
		}

	case TS_EV_PDCH_DEACT_ACK:
	case TS_EV_PDCH_DEACT_NACK:
		{
			struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);
			struct gsm_bts *bts = ts->trx->bts;
			/* Late PDCH deactivation ACK/NACK is also not a crime.
			 * Just process them as normal. */
			rate_ctr_inc(&bts->bts_ctrs->ctr[BTS_CTR_TS_BORKEN_EV_PDCH_DEACT_ACK_NACK]);
			osmo_stat_item_dec(bts->bts_statg->items[BTS_STAT_TS_BORKEN], 1);
			ts_fsm_wait_pdch_deact(fi, event, data);
			return;
		}

	default:
		OSMO_ASSERT(false);
	}
}

static int ts_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->state) {
	case TS_ST_WAIT_PDCH_ACT:
		ts_fsm_error(fi, TS_ST_BORKEN, "PDCH activation timeout");
		return 0;

	case TS_ST_WAIT_PDCH_DEACT:
		ts_fsm_error(fi, TS_ST_BORKEN, "PDCH deactivation timeout");
		return 0;

	default:
		ts_fsm_error(fi, TS_ST_BORKEN, "Unknown timeout in state %s",
			     osmo_fsm_inst_state_name(fi));
		return 0;
	}
}

static void ts_fsm_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);
	switch (event) {
	case TS_EV_OML_DOWN:
		ts->is_oml_ready = false;
		if (fi->state != TS_ST_NOT_INITIALIZED)
			osmo_fsm_inst_state_chg(fi, TS_ST_NOT_INITIALIZED, 0, 0);
		OSMO_ASSERT(fi->state == TS_ST_NOT_INITIALIZED);
		ts_terminate_lchan_fsms(ts);
		ts->pchan_is = ts->pchan_on_init = GSM_PCHAN_NONE;
		ts_fsm_update_id(ts);
		break;

	case TS_EV_RSL_DOWN:
		ts->is_rsl_ready = false;
		if (fi->state != TS_ST_NOT_INITIALIZED)
			osmo_fsm_inst_state_chg(fi, TS_ST_NOT_INITIALIZED, 0, 0);
		OSMO_ASSERT(fi->state == TS_ST_NOT_INITIALIZED);
		ts->pchan_is = GSM_PCHAN_NONE;
		ts_lchans_dispatch(ts, -1, LCHAN_EV_TS_ERROR);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static void ts_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct gsm_bts_trx_ts *ts = ts_fi_ts(fi);
	struct gsm_bts *bts = ts->trx->bts;
	if (ts->fi->state == TS_ST_BORKEN) {
		rate_ctr_inc(&bts->bts_ctrs->ctr[BTS_CTR_TS_BORKEN_EV_TEARDOWN]);
		osmo_stat_item_dec(bts->bts_statg->items[BTS_STAT_TS_BORKEN], 1);
	}
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state ts_fsm_states[] = {
	[TS_ST_NOT_INITIALIZED] = {
		.name = "NOT_INITIALIZED",
		.action = ts_fsm_not_initialized,
		.in_event_mask = 0
			| S(TS_EV_OML_READY)
			| S(TS_EV_RSL_READY)
			| S(TS_EV_LCHAN_REQUESTED)
			| S(TS_EV_LCHAN_UNUSED)
			,
		.out_state_mask = 0
			| S(TS_ST_UNUSED)
			| S(TS_ST_BORKEN)
			,
	},
	[TS_ST_UNUSED] = {
		.name = "UNUSED",
		.onenter = ts_fsm_unused_onenter,
		.action = ts_fsm_unused,
		.in_event_mask = 0
			| S(TS_EV_LCHAN_REQUESTED)
			| S(TS_EV_LCHAN_UNUSED)
			,
		.out_state_mask = 0
			| S(TS_ST_WAIT_PDCH_ACT)
			| S(TS_ST_IN_USE)
			| S(TS_ST_NOT_INITIALIZED)
			| S(TS_ST_BORKEN)
			,
	},
	[TS_ST_WAIT_PDCH_ACT] = {
		.name = "WAIT_PDCH_ACT",
		.onenter = ts_fsm_wait_pdch_act_onenter,
		.action = ts_fsm_wait_pdch_act,
		.in_event_mask = 0
			| S(TS_EV_PDCH_ACT_ACK)
			| S(TS_EV_PDCH_ACT_NACK)
			| S(TS_EV_LCHAN_REQUESTED)
			| S(TS_EV_LCHAN_UNUSED)
			,
		.out_state_mask = 0
			| S(TS_ST_PDCH)
			| S(TS_ST_UNUSED)
			| S(TS_ST_BORKEN)
			| S(TS_ST_NOT_INITIALIZED)
			,
	},
	[TS_ST_PDCH] = {
		.name = "PDCH",
		.onenter = ts_fsm_pdch_onenter,
		.action = ts_fsm_pdch,
		.in_event_mask = 0
			| S(TS_EV_LCHAN_REQUESTED)
			| S(TS_EV_LCHAN_UNUSED)
			,
		.out_state_mask = 0
			| S(TS_ST_WAIT_PDCH_DEACT)
			| S(TS_ST_NOT_INITIALIZED)
			| S(TS_ST_BORKEN)
			,
	},
	[TS_ST_WAIT_PDCH_DEACT] = {
		.name = "WAIT_PDCH_DEACT",
		.onenter = ts_fsm_wait_pdch_deact_onenter,
		.action = ts_fsm_wait_pdch_deact,
		.in_event_mask = 0
			| S(TS_EV_PDCH_DEACT_ACK)
			| S(TS_EV_PDCH_DEACT_NACK)
			| S(TS_EV_LCHAN_REQUESTED)
			| S(TS_EV_LCHAN_UNUSED)
			,
		.out_state_mask = 0
			| S(TS_ST_IN_USE)
			| S(TS_ST_UNUSED)
			| S(TS_ST_BORKEN)
			| S(TS_ST_NOT_INITIALIZED)
			| S(TS_ST_BORKEN)
			,
	},
	[TS_ST_IN_USE] = {
		.name = "IN_USE",
		.onenter = ts_fsm_in_use_onenter,
		.action = ts_fsm_in_use,
		.in_event_mask = 0
			| S(TS_EV_LCHAN_REQUESTED)
			| S(TS_EV_LCHAN_UNUSED)
			,
		.out_state_mask = 0
			| S(TS_ST_UNUSED)
			| S(TS_ST_NOT_INITIALIZED)
			| S(TS_ST_BORKEN)
			,
	},
	[TS_ST_BORKEN] = {
		.name = "BORKEN",
		.onenter = ts_fsm_borken_onenter,
		.action = ts_fsm_borken,
		.in_event_mask = 0
			| S(TS_EV_LCHAN_REQUESTED)
			| S(TS_EV_LCHAN_UNUSED)
			| S(TS_EV_PDCH_ACT_ACK)
			| S(TS_EV_PDCH_ACT_NACK)
			| S(TS_EV_PDCH_DEACT_ACK)
			| S(TS_EV_PDCH_DEACT_NACK)
			,
		.out_state_mask = 0
			| S(TS_ST_IN_USE)
			| S(TS_ST_UNUSED)
			| S(TS_ST_NOT_INITIALIZED)
			| S(TS_ST_PDCH)
			,
	},

};

static const struct value_string ts_fsm_event_names[] = {
	OSMO_VALUE_STRING(TS_EV_OML_READY),
	OSMO_VALUE_STRING(TS_EV_OML_DOWN),
	OSMO_VALUE_STRING(TS_EV_RSL_READY),
	OSMO_VALUE_STRING(TS_EV_RSL_DOWN),
	OSMO_VALUE_STRING(TS_EV_LCHAN_REQUESTED),
	OSMO_VALUE_STRING(TS_EV_LCHAN_UNUSED),
	OSMO_VALUE_STRING(TS_EV_PDCH_ACT_ACK),
	OSMO_VALUE_STRING(TS_EV_PDCH_ACT_NACK),
	OSMO_VALUE_STRING(TS_EV_PDCH_DEACT_ACK),
	OSMO_VALUE_STRING(TS_EV_PDCH_DEACT_NACK),
	{}
};

static struct osmo_fsm ts_fsm = {
	.name = "timeslot",
	.states = ts_fsm_states,
	.num_states = ARRAY_SIZE(ts_fsm_states),
	.timer_cb = ts_fsm_timer_cb,
	.log_subsys = DTS,
	.event_names = ts_fsm_event_names,
	.allstate_event_mask = 0
		| S(TS_EV_OML_DOWN)
		| S(TS_EV_RSL_DOWN)
		,
	.allstate_action = ts_fsm_allstate,
	.cleanup = ts_fsm_cleanup,
};

/* Return true if any lchans are waiting for this timeslot to become a specific PCHAN. If target_pchan is
 * not NULL, also return the PCHAN being waited for. */
bool ts_is_lchan_waiting_for_pchan(struct gsm_bts_trx_ts *ts, enum gsm_phys_chan_config *target_pchan)
{
	struct gsm_lchan *lchan;
	ts_for_each_potential_lchan(lchan, ts) {
		if (lchan->fi->state == LCHAN_ST_WAIT_TS_READY) {
			if (target_pchan)
				*target_pchan = gsm_pchan_by_lchan_type(lchan->type);
			return true;
		}
	}
	return false;
}

/* Return true if we are busy changing the PCHAN kind. If target_pchan is not NULL, also return the PCHAN
 * (ultimately) being switched to. */
bool ts_is_pchan_switching(struct gsm_bts_trx_ts *ts, enum gsm_phys_chan_config *target_pchan)
{
	switch (ts->fi->state) {
	case TS_ST_NOT_INITIALIZED:
	case TS_ST_BORKEN:
		return false;
	default:
		break;
	}

	/* If an lchan is waiting, return the final pchan after all switching is done. */
	if (ts_is_lchan_waiting_for_pchan(ts, target_pchan))
		return true;

	/* No lchans waiting. Return any ongoing switching. */

	switch (ts->fi->state) {
	case TS_ST_WAIT_PDCH_ACT:
		/* When switching to PDCH, there are no lchans and we are
		 * telling the PCU to take over the timeslot. */
		if (target_pchan)
			*target_pchan = GSM_PCHAN_PDCH;
		return true;

	case TS_ST_WAIT_PDCH_DEACT:
		/* If lchan started a PDCH deact but got somehow released while
		 * waiting for PDCH DEACT (N)ACK */
		if (target_pchan) {
			switch (ts->pchan_on_init) {
			case GSM_PCHAN_TCH_F_TCH_H_PDCH:
				if (target_pchan)
					*target_pchan = GSM_PCHAN_NONE;
				break;
			case GSM_PCHAN_TCH_F_PDCH:
				if (target_pchan)
					*target_pchan = GSM_PCHAN_TCH_F;
				break;
			default:
				/* Can't be in this state and be a non dyn TS */
				OSMO_ASSERT(false);
			}
		}
		return true;

	default:
		return false;
	}
}

/* Does the timeslot's *current* state allow use as this PCHAN kind? If the ts is in switchover, return
 * true if the switchover's target PCHAN matches, i.e. an lchan for this pchan kind could be requested
 * and will be served after the switch. (Do not check whether any lchans are actually available.) */
bool ts_usable_as_pchan(struct gsm_bts_trx_ts *ts, enum gsm_phys_chan_config as_pchan, bool allow_pchan_switch)
{
	enum gsm_phys_chan_config target_pchan;

	if (!ts_is_usable(ts))
		return false;

	switch (ts->fi->state) {
	case TS_ST_IN_USE:
		return ts->pchan_is == as_pchan;

	default:
		break;
	}

	if (ts_is_lchan_waiting_for_pchan(ts, &target_pchan))
		return target_pchan == as_pchan;

	if (!ts_is_capable_of_pchan(ts, as_pchan))
		return false;

	if (!allow_pchan_switch && ts->pchan_is != as_pchan)
		return false;

	return true;
}
