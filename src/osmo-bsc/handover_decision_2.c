/* Handover Decision Algorithm 2 for intra-BSC (inter-BTS) handover, public API for OsmoBSC. */

/* (C) 2009 by Andreas Eversberg <jolly@eversberg.eu>
 * (C) 2017-2018 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * Author: Andreas Eversberg <jolly@eversberg.eu>
 *         Neels Hofmeyr <nhofmeyr@sysmocom.de>
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
 */

#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <math.h>

#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/handover_fsm.h>
#include <osmocom/bsc/handover_decision.h>
#include <osmocom/bsc/handover_decision_2.h>
#include <osmocom/bsc/handover_cfg.h>
#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/lchan_fsm.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/penalty_timers.h>
#include <osmocom/bsc/neighbor_ident.h>
#include <osmocom/bsc/timeslot_fsm.h>
#include <osmocom/bsc/bts.h>
#include <osmocom/bsc/lchan_select.h>

#define LOGPHOBTS(bts, level, fmt, args...) \
	LOGP(DHODEC, level, "(BTS %u) " fmt, bts->nr, ## args)

#define LOGPHOLCHAN(lchan, level, fmt, args...) \
	LOGP(DHODEC, level, "(lchan %u.%u%u%u %s %s) (subscr %s) " fmt, \
	     lchan->ts->trx->bts->nr, \
	     lchan->ts->trx->nr, \
	     lchan->ts->nr, \
	     lchan->nr, \
	     gsm_lchant_name(lchan->type), \
	     gsm48_chan_mode_name(lchan->tch_mode), \
	     bsc_subscr_name(lchan->conn? lchan->conn->bsub : NULL), \
	     ## args)

#define LOGPHOLCHANTOBTS(lchan, new_bts, level, fmt, args...) \
	LOGP(DHODEC, level, "(lchan %u.%u%u%u %s %s)->(BTS %u) (subscr %s) " fmt, \
	     lchan->ts->trx->bts->nr, \
	     lchan->ts->trx->nr, \
	     lchan->ts->nr, \
	     lchan->nr, \
	     gsm_lchant_name(lchan->type), \
	     gsm48_chan_mode_name(lchan->tch_mode), \
	     new_bts->nr, \
	     bsc_subscr_name(lchan->conn? lchan->conn->bsub : NULL), \
	     ## args)

#define LOGPHOLCHANTOREMOTE(lchan, remote_cil, level, fmt, args...) \
	LOGP(DHODEC, level, "(lchan %u.%u%u%u %s %s)->(remote-BSS %s) (subscr %s) " fmt, \
	     lchan->ts->trx->bts->nr, \
	     lchan->ts->trx->nr, \
	     lchan->ts->nr, \
	     lchan->nr, \
	     gsm_lchant_name(lchan->type), \
	     gsm48_chan_mode_name(lchan->tch_mode), \
	     gsm0808_cell_id_list_name(remote_cil), \
	     bsc_subscr_name(lchan->conn? lchan->conn->bsub : NULL), \
	     ## args)

#define LOGPHOCAND(candidate, level, fmt, args...) do {\
	if ((candidate)->target.bts) \
		LOGPHOLCHANTOBTS((candidate)->current.lchan, (candidate)->target.bts, level, fmt, ## args); \
	else if ((candidate)->target.cil) \
		LOGPHOLCHANTOREMOTE((candidate)->current.lchan, (candidate)->target.cil, level, fmt, ## args); \
	} while(0)


#define REQUIREMENT_A_TCHF	0x01
#define REQUIREMENT_B_TCHF	0x02
#define REQUIREMENT_C_TCHF	0x04
#define REQUIREMENT_A_TCHH	0x10
#define REQUIREMENT_B_TCHH	0x20
#define REQUIREMENT_C_TCHH	0x40
#define REQUIREMENT_TCHF_MASK	(REQUIREMENT_A_TCHF | REQUIREMENT_B_TCHF | REQUIREMENT_C_TCHF)
#define REQUIREMENT_TCHH_MASK	(REQUIREMENT_A_TCHH | REQUIREMENT_B_TCHH | REQUIREMENT_C_TCHH)
#define REQUIREMENT_A_MASK	(REQUIREMENT_A_TCHF | REQUIREMENT_A_TCHH)
#define REQUIREMENT_B_MASK	(REQUIREMENT_B_TCHF | REQUIREMENT_B_TCHH)
#define REQUIREMENT_C_MASK	(REQUIREMENT_C_TCHF | REQUIREMENT_C_TCHH)

struct ho_candidate {
	uint8_t requirements;		/* what is fulfilled */
	struct {
		struct gsm_lchan *lchan;
		struct gsm_bts *bts;
		int rxlev;
		/* free/min-free for the current TCH kind, same as either free_tch_f or free_tch_h below */
		int free_tch;
		int min_free_tch;
		/* free/min-free for the two TCH kinds, to calculate F<->H cross effects for dynamic timeslots */
		int free_tchf;
		int min_free_tchf;
		int free_tchh;
		int min_free_tchh;
		/* Effects of freeing a dynamic timeslot, i.e. turning it into PDCH mode and making available more free
		 * TCH: */
		int lchan_frees_tchf;
		int lchan_frees_tchh;
	} current;
	struct {
		struct neighbor_ident_key nik;	/* neighbor ARFCN+BSIC */
		const struct gsm0808_cell_id_list2 *cil; /* target cells in remote BSS */
		struct gsm_bts *bts;
		int rxlev;
		int rxlev_afs_bias;
		int free_tchf;
		int min_free_tchf;
		int free_tchh;
		int min_free_tchh;
		/* Effects of occupying a dynamic timeslot, i.e. turning from PDCH into a specific TCH kind, and
		 * reducing the number of free TCH for both TCH/F and TCH/H: */
		int next_tchf_reduces_tchh;
		int next_tchh_reduces_tchf;
	} target;
};

enum ho_reason {
	HO_REASON_INTERFERENCE,
	HO_REASON_BAD_QUALITY,
	HO_REASON_LOW_RXLEVEL,
	HO_REASON_MAX_DISTANCE,
	HO_REASON_BETTER_CELL,
	HO_REASON_CONGESTION,
};

static const struct value_string ho_reason_names[] = {
	{ HO_REASON_INTERFERENCE,	"interference (bad quality)" },
	{ HO_REASON_BAD_QUALITY,	"bad quality" },
	{ HO_REASON_LOW_RXLEVEL,	"low rxlevel" },
	{ HO_REASON_MAX_DISTANCE,	"maximum allowed distance" },
	{ HO_REASON_BETTER_CELL,	"better cell" },
	{ HO_REASON_CONGESTION,		"congestion" },
	{0, NULL}
};

static const char *ho_reason_name(int value)
{
        return get_value_string(ho_reason_names, value);
}


static bool hodec2_initialized = false;
static enum ho_reason global_ho_reason;

static void congestion_check_cb(void *arg);

static unsigned int ts_usage_count(struct gsm_bts_trx_ts *ts)
{
	struct gsm_lchan *lchan;
	unsigned int count = 0;
	ts_for_each_lchan(lchan, ts) {
		if (lchan_state_is(lchan, LCHAN_ST_ESTABLISHED))
			count++;
	}
	return count;
}

/* This function gets called on ho2 init, whenever the congestion check interval is changed, and also
 * when the timer has fired to trigger again after the next congestion check timeout. */
static void reinit_congestion_timer(struct gsm_network *net)
{
	int congestion_check_interval_s;
	bool was_active;

	/* Don't setup timers from VTY config parsing before the main program has actually initialized
	 * the data structures. */
	if (!hodec2_initialized)
		return;

	was_active = net->hodec2.congestion_check_timer.active;
	if (was_active)
		osmo_timer_del(&net->hodec2.congestion_check_timer);

	congestion_check_interval_s = net->hodec2.congestion_check_interval_s;
	if (congestion_check_interval_s < 1) {
		if (was_active)
			LOGP(DHODEC, LOGL_NOTICE, "HO algorithm 2: Disabling congestion check\n");
		return;
	}


	osmo_timer_setup(&net->hodec2.congestion_check_timer,
			 congestion_check_cb, net);
	osmo_timer_schedule(&net->hodec2.congestion_check_timer,
			    0, congestion_check_interval_s * 1000);
}

void hodec2_on_change_congestion_check_interval(struct gsm_network *net, unsigned int new_interval)
{
	net->hodec2.congestion_check_interval_s = new_interval;
	reinit_congestion_timer(net);
}

static void _conn_penalty_time_add(struct gsm_subscriber_connection *conn,
				   const void *for_object,
				   int penalty_time)
{
	if (!for_object) {
		LOGP(DHODEC, LOGL_ERROR, "%s Unable to set Handover-2 penalty timer:"
		     " no target cell pointer\n",
		     bsc_subscr_name(conn->bsub));
		return;
	}

	if (!conn->hodec2.penalty_timers) {
		conn->hodec2.penalty_timers = penalty_timers_init(conn);
		OSMO_ASSERT(conn->hodec2.penalty_timers);
	}

	penalty_timers_add(conn->hodec2.penalty_timers, for_object, penalty_time);
}

static void nik_penalty_time_add(struct gsm_subscriber_connection *conn,
				 struct neighbor_ident_key *nik,
				 int penalty_time)
{
	_conn_penalty_time_add(conn,
			       neighbor_ident_get(conn->network->neighbor_bss_cells, nik),
			       penalty_time);
}

static void bts_penalty_time_add(struct gsm_subscriber_connection *conn,
				 struct gsm_bts *bts,
				 int penalty_time)
{
	_conn_penalty_time_add(conn, bts, penalty_time);
}

static unsigned int conn_penalty_time_remaining(struct gsm_subscriber_connection *conn,
						const void *for_object)
{
	if (!conn->hodec2.penalty_timers)
		return 0;
	return penalty_timers_remaining(conn->hodec2.penalty_timers, for_object);
}

/* did we get a RXLEV for a given cell in the given report? Mark matches as MRC_F_PROCESSED. */
static struct gsm_meas_rep_cell *cell_in_rep(struct gsm_meas_rep *mr, uint16_t arfcn, uint8_t bsic)
{
	int i;

	for (i = 0; i < mr->num_cell; i++) {
		struct gsm_meas_rep_cell *mrc = &mr->cell[i];

		if (mrc->arfcn != arfcn)
			continue;
		if (mrc->bsic != bsic)
			continue;

		return mrc;
	}
	return NULL;
}

static int current_rxlev(struct gsm_lchan *lchan)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	return get_meas_rep_avg(lchan,
				ho_get_hodec2_full_tdma(bts->ho) ?
					MEAS_REP_DL_RXLEV_FULL : MEAS_REP_DL_RXLEV_SUB,
				ho_get_hodec2_rxlev_avg_win(bts->ho));
}

/* obtain averaged rxlev for given neighbor */
static int neigh_meas_avg(struct neigh_meas_proc *nmp, int window)
{
	unsigned int i, idx;
	int avg = 0;

	/* reduce window to the actual number of existing measurements */
	if (window > nmp->rxlev_cnt)
		window = nmp->rxlev_cnt;
	/* this should never happen */
	if (window <= 0)
		return 0;

	idx = calc_initial_idx(ARRAY_SIZE(nmp->rxlev),
			       nmp->rxlev_cnt % ARRAY_SIZE(nmp->rxlev),
			       window);

	for (i = 0; i < window; i++) {
		int j = (idx+i) % ARRAY_SIZE(nmp->rxlev);

		avg += nmp->rxlev[j];
	}

	return avg / window;
}

/* Find empty slot or the worst neighbor. */
static struct neigh_meas_proc *find_unused_or_worst_neigh(struct gsm_lchan *lchan)
{
	struct neigh_meas_proc *nmp_worst = NULL;
	int worst;
	int j;

	/* First try to find an empty/unused slot. */
	for (j = 0; j < ARRAY_SIZE(lchan->neigh_meas); j++) {
		struct neigh_meas_proc *nmp = &lchan->neigh_meas[j];
		if (!nmp->arfcn)
			return nmp;
	}

	/* No empty slot found. Return worst neighbor to be evicted. */
	worst = 0; /* (overwritten on first loop, but avoid compiler warning) */
	for (j = 0; j < ARRAY_SIZE(lchan->neigh_meas); j++) {
		struct neigh_meas_proc *nmp = &lchan->neigh_meas[j];
		int avg = neigh_meas_avg(nmp, MAX_WIN_NEIGH_AVG);
		if (nmp_worst && avg >= worst)
			continue;
		worst = avg;
		nmp_worst = nmp;
	}

	return nmp_worst;
}

/* process neighbor cell measurement reports */
static void process_meas_neigh(struct gsm_meas_rep *mr)
{
	int i, j, idx;

	/* For each reported cell, try to update measurements we already have from previous reports. */
	for (j = 0; j < ARRAY_SIZE(mr->lchan->neigh_meas); j++) {
		struct neigh_meas_proc *nmp = &mr->lchan->neigh_meas[j];
		unsigned int idx;
		struct gsm_meas_rep_cell *mrc;

		/* skip unused entries */
		if (!nmp->arfcn)
			continue;

		mrc = cell_in_rep(mr, nmp->arfcn, nmp->bsic);
		idx = nmp->rxlev_cnt % ARRAY_SIZE(nmp->rxlev);
		if (mrc) {
			nmp->rxlev[idx] = mrc->rxlev;
			nmp->last_seen_nr = mr->nr;
			mrc->flags |= MRC_F_PROCESSED;
		} else {
			nmp->rxlev[idx] = 0;
		}
		nmp->rxlev_cnt++;
	}

	/* Add cells that we don't know about yet, if necessary overwriting previous records that reflect
	 * cells with worse receive levels */
	for (i = 0; i < mr->num_cell; i++) {
		struct gsm_meas_rep_cell *mrc = &mr->cell[i];
		struct neigh_meas_proc *nmp;

		if (mrc->flags & MRC_F_PROCESSED)
			continue;

		nmp = find_unused_or_worst_neigh(mr->lchan);

		nmp->arfcn = mrc->arfcn;
		nmp->bsic = mrc->bsic;

		nmp->rxlev_cnt = 0;
		idx = nmp->rxlev_cnt % ARRAY_SIZE(nmp->rxlev);
		nmp->rxlev[idx] = mrc->rxlev;
		nmp->rxlev_cnt++;
		nmp->last_seen_nr = mr->nr;
		LOGPHOLCHAN(mr->lchan, LOGL_DEBUG, "neigh %u new in report rxlev=%d last_seen_nr=%u\n",
			    nmp->arfcn, mrc->rxlev, nmp->last_seen_nr);

		mrc->flags |= MRC_F_PROCESSED;
	}
}

static bool codec_type_is_supported(struct gsm_subscriber_connection *conn,
				    enum gsm0808_speech_codec_type type)
{
	int i;
	struct gsm0808_speech_codec_list *clist = &conn->codec_list;

	if (!conn->codec_list.len) {
		/* We don't have a list of supported codecs. This should never happen. */
		LOGPHOLCHAN(conn->lchan, LOGL_ERROR,
			    "No Speech Codec List present, accepting all codecs\n");
		return true;
	}

	for (i = 0; i < clist->len; i++) {
		if (clist->codec[i].type == type)
			return true;
	}
	LOGPHOLCHAN(conn->lchan, LOGL_DEBUG, "Codec not supported by MS or not allowed by MSC: %s\n",
		    gsm0808_speech_codec_type_name(type));
	return false;
}

#define LOAD_PRECISION 6

/* Return a number representing overload, i.e. the fraction of lchans used above the congestion threshold.
 * Think of it as a percentage of used lchans above congestion, just represented in a fixed-point fraction with N
 * decimal digits of fractional part. If there is no congestion (free_tch >= min_free_tch), return 0.
 */
static int32_t load_above_congestion(int free_tch, int min_free_tch)
{
	int32_t v;
	OSMO_ASSERT(free_tch >= 0);
	/* Avoid division by zero when no congestion threshold is set, and return zero overload when there is no
	 * congestion. */
	if (free_tch >= min_free_tch)
		return 0;
	v = min_free_tch - free_tch;
	v *= pow(10, LOAD_PRECISION);
	v /= min_free_tch;
	return v;
}

/*
 * Check what requirements the given cell fulfills.
 * A bit mask of fulfilled requirements is returned.
 *
 * Target cell requirement A -- ability to service the call
 *
 * In order to successfully handover/assign to a better cell, the target cell
 * must be able to continue the current call. Therefore the cell must fulfill
 * the following criteria:
 *
 *  * The handover must be enabled for the target cell, if it differs from the
 *    originating cell.
 *  * The assignment must be enabled for the cell, if it equals the current
 *    cell.
 *  * The handover penalty timer must not run for the cell.
 *  * If FR, EFR or HR codec is used, the cell must support this codec.
 *  * If FR or EFR codec is used, the cell must have a TCH/F slot type
 *    available.
 *  * If HR codec is used, the cell must have a TCH/H slot type available.
 *  * If AMR codec is used, the cell must have a TCH/F slot available, if AFS
 *    is supported by mobile and BTS.
 *  * If AMR codec is used, the cell must have a TCH/H slot available, if AHS
 *    is supported by mobile and BTS.
 *  * osmo-nitb with built-in MNCC application:
 *     o If AMR codec is used, the cell must support AMR codec with equal codec
 *       rate or rates. (not meaning TCH types)
 *  * If defined, the number of maximum unsynchronized handovers to this cell
 *    may not be exceeded. (This limits processing load for random access
 *    bursts.)
 *
 *
 * Target cell requirement B -- avoid congestion
 *
 * In order to prevent congestion of a target cell, the cell must fulfill the
 * requirement A, but also:
 *
 *  * The minimum free channels, that are defined for that cell must be
 *    maintained after handover/assignment.
 *  * The minimum free channels are defined for TCH/F and TCH/H slot types
 *    individually.
 *
 *
 * Target cell requirement C -- balance congestion
 *
 * In order to balance congested cells, the target cell must fulfill the
 * requirement A, but also:
 *
 *  * The target cell (which is congested also) must have more or equal free
 *    slots after handover/assignment.
 *  * The number of free slots are checked for TCH/F and TCH/H slot types
 *    individually.
 */
static void check_requirements(struct ho_candidate *c)
{
	uint8_t requirement = 0;
	unsigned int penalty_time;
	int32_t current_overbooked;
	c->requirements = 0;

	/* Requirement A */

	/* the handover/assignment must not be disabled */
	if (c->current.bts == c->target.bts) {
		if (!ho_get_hodec2_as_active(c->target.bts->ho)) {
			LOGPHOLCHAN(c->current.lchan, LOGL_DEBUG, "Assignment disabled\n");
			return;
		}
	} else {
		if (!ho_get_ho_active(c->target.bts->ho)) {
			LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_DEBUG,
					 "not a candidate, handover is disabled in target BTS\n");
			return;
		}
	}

	/* the handover penalty timer must not run for this bts */
	penalty_time = conn_penalty_time_remaining(c->current.lchan->conn, c->target.bts);
	if (penalty_time) {
		LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_DEBUG, "not a candidate, target BTS still in penalty time"
				 " (%u seconds left)\n", penalty_time);
		return;
	}

	/* compatibility check for codecs.
	 * if so, the candidates for full rate and half rate are selected */
	switch (c->current.lchan->tch_mode) {
	case GSM48_CMODE_SPEECH_V1:
		switch (c->current.lchan->type) {
		case GSM_LCHAN_TCH_F: /* mandatory */
			requirement |= REQUIREMENT_A_TCHF;
			break;
		case GSM_LCHAN_TCH_H:
			if (!c->target.bts->codec.hr) {
				LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_DEBUG,
						 "tch_mode='%s' type='%s' not supported\n",
						 get_value_string(gsm48_chan_mode_names,
								  c->current.lchan->tch_mode),
						 gsm_lchant_name(c->current.lchan->type));
				break;
			}
			if (codec_type_is_supported(c->current.lchan->conn, GSM0808_SCT_HR1))
				requirement |= REQUIREMENT_A_TCHH;
			break;
		default:
			LOGPHOLCHAN(c->current.lchan, LOGL_ERROR, "Unexpected channel type: neither TCH/F nor TCH/H for %s\n",
				    get_value_string(gsm48_chan_mode_names, c->current.lchan->tch_mode));
			return;
		}
		break;
	case GSM48_CMODE_SPEECH_EFR:
		if (!c->target.bts->codec.efr) {
			LOGPHOBTS(c->target.bts, LOGL_DEBUG, "EFR not supported\n");
			break;
		}
		if (codec_type_is_supported(c->current.lchan->conn, GSM0808_SCT_FR2))
			requirement |= REQUIREMENT_A_TCHF;
		break;
	case GSM48_CMODE_SPEECH_AMR:
		if (!c->target.bts->codec.amr) {
			LOGPHOBTS(c->target.bts, LOGL_DEBUG, "AMR not supported\n");
			break;
		}
		if (codec_type_is_supported(c->current.lchan->conn, GSM0808_SCT_FR3))
			requirement |= REQUIREMENT_A_TCHF;
		if (codec_type_is_supported(c->current.lchan->conn, GSM0808_SCT_HR3))
			requirement |= REQUIREMENT_A_TCHH;
		break;
	default:
		LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_DEBUG, "Not even considering: src is not a SPEECH mode lchan\n");
		/* FIXME: should allow handover of non-speech lchans */
		return;
	}

	/* no candidate, because new cell is incompatible */
	if (!requirement) {
		LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_DEBUG, "not a candidate, because codec of MS and BTS are incompatible\n");
		return;
	}

	/* remove slot types that are not available */
	if (!c->target.free_tchf && (requirement & REQUIREMENT_A_TCHF)) {
		LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_DEBUG,
				 "removing TCH/F, since all TCH/F lchans are in use\n");
		requirement &= ~(REQUIREMENT_A_TCHF);
	}
	if (!c->target.free_tchh && (requirement & REQUIREMENT_A_TCHH)) {
		LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_DEBUG,
				 "removing TCH/H, since all TCH/H lchans are in use\n");
		requirement &= ~(REQUIREMENT_A_TCHH);
	}

	if (!requirement) {
		LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_DEBUG, "not a candidate, because no suitable slots available\n");
		return;
	}

	/* omit same channel type on same BTS (will not change anything) */
	if (c->target.bts == c->current.bts) {
		switch (c->current.lchan->type) {
		case GSM_LCHAN_TCH_F:
			requirement &= ~(REQUIREMENT_A_TCHF);
			break;
		case GSM_LCHAN_TCH_H:
			requirement &= ~(REQUIREMENT_A_TCHH);
			break;
		default:
			break;
		}

		if (!requirement) {
			LOGPHOLCHAN(c->current.lchan, LOGL_DEBUG,
				    "Reassignment within cell not an option, no differing channel types available\n");
			return;
		}
	}

#ifdef LEGACY
	// This was useful in osmo-nitb. We're in osmo-bsc now and have no idea whether the osmo-msc does
	// internal or external call control. Maybe a future config switch wants to add this behavior?
	/* Built-in call control requires equal codec rates. Remove rates that are not equal. */
	if (c->current.lchan->tch_mode == GSM48_CMODE_SPEECH_AMR
	    && c->current.bts->network->mncc_recv != mncc_sock_from_cc) {
		switch (c->current.lchan->type) {
		case GSM_LCHAN_TCH_F:
			if ((requirement & REQUIREMENT_A_TCHF)
			    && !!memcmp(&c->current.bts->mr_full, &c->target.bts->mr_full,
					sizeof(struct amr_multirate_conf)))
				requirement &= ~(REQUIREMENT_A_TCHF);
			if ((requirement & REQUIREMENT_A_TCHH)
			    && !!memcmp(&c->current.bts->mr_full, &c->target.bts->mr_half,
					sizeof(struct amr_multirate_conf)))
				requirement &= ~(REQUIREMENT_A_TCHH);
			break;
		case GSM_LCHAN_TCH_H:
			if ((requirement & REQUIREMENT_A_TCHF)
			    && !!memcmp(&c->current.bts->mr_half, &c->target.bts->mr_full,
					sizeof(struct amr_multirate_conf)))
				requirement &= ~(REQUIREMENT_A_TCHF);
			if ((requirement & REQUIREMENT_A_TCHH)
			    && !!memcmp(&c->current.bts->mr_half, &c->target.bts->mr_half,
					sizeof(struct amr_multirate_conf)))
				requirement &= ~(REQUIREMENT_A_TCHH);
			break;
		default:
			break;
		}

		if (!requirement) {
			LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_DEBUG,
					 "not a candidate, cannot provide identical codec rate\n");
			return;
		}
	}
#endif

	/* the maximum number of unsynchronized handovers must no be exceeded */
	if (c->current.bts != c->target.bts
	    && bts_handover_count(c->target.bts, HO_SCOPE_ALL) >= ho_get_hodec2_ho_max(c->target.bts->ho)) {
		LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_DEBUG,
				 "not a candidate, number of allowed handovers (%d) would be exceeded\n",
				 ho_get_hodec2_ho_max(c->target.bts->ho));
		return;
	}

	/* Requirement B */

	/* the minimum free timeslots that are defined for this cell must
	 * be maintained _after_ handover/assignment */
	if (requirement & REQUIREMENT_A_TCHF) {
		if ((c->target.free_tchf - 1) >= c->target.min_free_tchf
		    && (!c->target.next_tchf_reduces_tchh
			|| (c->target.free_tchh - c->target.next_tchf_reduces_tchh) >= c->target.min_free_tchh))
			requirement |= REQUIREMENT_B_TCHF;
	}
	if (requirement & REQUIREMENT_A_TCHH) {
		if ((c->target.free_tchh - 1) >= c->target.min_free_tchh
		    && (!c->target.next_tchh_reduces_tchf
			|| (c->target.free_tchf - c->target.next_tchh_reduces_tchf) >= c->target.min_free_tchf))
			requirement |= REQUIREMENT_B_TCHH;
	}

	/* Requirement C */

	/* the load percentage above congestion on the target cell *after* HO must be < the load percentage above
	 * congestion on the current cell, hence the - 1 on the target. */
	current_overbooked = load_above_congestion(c->current.free_tch, c->current.min_free_tch);
	if (requirement & REQUIREMENT_A_TCHF) {
		bool ok;
		int32_t target_overbooked;
		int target_free_tchf_after_ho;

		/* To evaluate whether a handover improves or worsens congestion on TCH/F, first figure out how many
		 * TCH/F lchans will be occupied on the target after the handover. If the target is a different cell,
		 * then we obviously reduce by one TCH/F. If source and target cell are the same (re-assignment), then
		 * the source lchan may also free a TCH/F at the same time. Add up all of these effects to figure out
		 * the congestion percentages before and after handover. */
		target_free_tchf_after_ho = c->target.free_tchf - 1;
		if (c->current.bts == c->target.bts)
			target_free_tchf_after_ho += c->current.lchan_frees_tchf;
		target_overbooked = load_above_congestion(target_free_tchf_after_ho, c->target.min_free_tchf);
		LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_DEBUG,
				 "current overbooked = %s%%, TCH/F target overbooked after HO = %s%%\n",
				 osmo_int_to_float_str_c(OTC_SELECT, current_overbooked, LOAD_PRECISION - 2),
				 osmo_int_to_float_str_c(OTC_SELECT, target_overbooked, LOAD_PRECISION - 2));
		ok = target_overbooked < current_overbooked;
		/* Look at dynamic timeslot effects on TCH/H: */
		if (ok && c->target.next_tchf_reduces_tchh) {
			/* Looking at the current TCH type and the target cell's TCH/F alone, congestion balancing
			 * should happen. However, what if the target TCH/F is a dynamic timeslot -- would that cause
			 * congestion on TCH/H above the current cell's TCH/H congestion? */
			int32_t current_tchh_overbooked = load_above_congestion(c->current.free_tchh,
										c->current.min_free_tchh);
			int32_t target_tchh_overbooked;
			int target_free_tchh_after_ho = c->target.free_tchh - c->target.next_tchf_reduces_tchh;
			/* If this is a re-assignment within the same cell, and if the current candidate would free a
			 * dynamic timeslot, then the target-overbooking after HO is reduced again by the freed dynamic
			 * TS. */
			if (c->current.bts == c->target.bts)
				target_free_tchh_after_ho += c->current.lchan_frees_tchh;
			target_tchh_overbooked = load_above_congestion(target_free_tchh_after_ho,
								       c->target.min_free_tchh);
			LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_DEBUG,
					 "dyn TS: current TCH/H overbooked = %s%%, TCH/H target overbooked after HO = %s%%\n",
					 osmo_int_to_float_str_c(OTC_SELECT, current_tchh_overbooked, LOAD_PRECISION - 2),
					 osmo_int_to_float_str_c(OTC_SELECT, target_tchh_overbooked, LOAD_PRECISION - 2));
			/* For the current TCH kind, a handover should only happen if things actually get better
			 * (condition is '<'). For dynamic timeslot cross effects TCH/F->TCH/H, it is fine to not make
			 * it worse.  Hence the smaller-or-equal condition. */
			ok = target_tchh_overbooked <= current_tchh_overbooked;
		}
		if (ok)
			requirement |= REQUIREMENT_C_TCHF;
	}
	if (requirement & REQUIREMENT_A_TCHH) {
		bool ok;
		int32_t target_overbooked;
		int target_free_tchh_after_ho;

		/* To evaluate whether a handover improves or worsens congestion on TCH/H, first figure out how many
		 * TCH/H lchans will be occupied on the target after the handover. If the target is a different cell,
		 * then we obviously reduce by one TCH/H. If source and target cell are the same (re-assignment), then
		 * the source lchan may also free one or two TCH/H at the same time. Add up all of these effects to
		 * figure out the congestion percentages before and after handover. */
		target_free_tchh_after_ho = c->target.free_tchh - 1;
		if (c->current.bts == c->target.bts)
			target_free_tchh_after_ho += c->current.lchan_frees_tchh;
		target_overbooked = load_above_congestion(target_free_tchh_after_ho, c->target.min_free_tchh);
		LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_DEBUG,
				 "current overbooked = %s%%, TCH/H target overbooked after HO = %s%%\n",
				 osmo_int_to_float_str_c(OTC_SELECT, current_overbooked, LOAD_PRECISION - 2),
				 osmo_int_to_float_str_c(OTC_SELECT, target_overbooked, LOAD_PRECISION - 2));
		ok = target_overbooked < current_overbooked;
		/* Look at dynamic timeslot effects on TCH/F: */
		if (ok && c->target.next_tchh_reduces_tchf) {
			/* Looking at the current TCH type and the target cell's TCH/H alone, congestion balancing
			 * should happen. However, what if the target TCH/H is a dynamic timeslot -- would that cause
			 * congestion on TCH/F above the current cell's TCH/F congestion? */
			int32_t current_tchf_overbooked = load_above_congestion(c->current.free_tchf,
										c->current.min_free_tchf);
			int32_t target_tchf_overbooked;
			int target_free_tchf_after_ho = c->target.free_tchf - c->target.next_tchh_reduces_tchf;
			/* If this is a re-assignment within the same cell, and if the current candidate would free a
			 * dynamic timeslot, then the target-overbooking after HO is reduced again by the freed dynamic
			 * TS. */
			if (c->current.bts == c->target.bts)
				target_free_tchf_after_ho += c->current.lchan_frees_tchf;
			target_tchf_overbooked = load_above_congestion(target_free_tchf_after_ho,
								       c->target.min_free_tchf);
			LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_DEBUG,
					 "dyn TS: current TCH/F overbooked = %s%%, TCH/F target overbooked after HO = %s%%\n",
					 osmo_int_to_float_str_c(OTC_SELECT, current_tchf_overbooked, LOAD_PRECISION - 2),
					 osmo_int_to_float_str_c(OTC_SELECT, target_tchf_overbooked, LOAD_PRECISION - 2));
			/* For the current TCH kind, a handover should only happen if things actually get better
			 * (condition is '<'). For dynamic timeslot cross effects TCH/H->TCH/F, it is fine to not make
			 * it worse. Hence the smaller-or-equal condition. */
			ok = target_tchf_overbooked <= current_tchf_overbooked;
		}
		if (ok)
			requirement |= REQUIREMENT_C_TCHH;
	}

	/* return mask of fulfilled requirements */
	c->requirements = requirement;
}

static void check_requirements_remote_bss(struct ho_candidate *c)
{
	uint8_t requirement = 0;
	unsigned int penalty_time;
	c->requirements = 0;

	/* Requirement A */

	/* the handover penalty timer must not run for this bts */
	penalty_time = conn_penalty_time_remaining(c->current.lchan->conn, c->target.cil);
	if (penalty_time) {
		LOGPHOLCHANTOREMOTE(c->current.lchan, c->target.cil, LOGL_DEBUG,
				    "not a candidate, target BSS still in penalty time"
				    " (%u seconds left)\n", penalty_time);
		return;
	}

	/* compatibility check for codecs -- we have no notion of what the remote BSS supports. We can
	 * only assume that a handover would work, and use only the local requirements. */
	switch (c->current.lchan->tch_mode) {
	case GSM48_CMODE_SPEECH_V1:
		switch (c->current.lchan->type) {
		case GSM_LCHAN_TCH_F: /* mandatory */
			requirement |= REQUIREMENT_A_TCHF;
			break;
		case GSM_LCHAN_TCH_H:
			if (codec_type_is_supported(c->current.lchan->conn, GSM0808_SCT_HR1))
				requirement |= REQUIREMENT_A_TCHH;
			break;
		default:
			LOGPHOLCHAN(c->current.lchan, LOGL_ERROR, "Unexpected channel type: neither TCH/F nor TCH/H for %s\n",
				    get_value_string(gsm48_chan_mode_names, c->current.lchan->tch_mode));
			return;
		}
		break;
	case GSM48_CMODE_SPEECH_EFR:
		if (codec_type_is_supported(c->current.lchan->conn, GSM0808_SCT_FR2))
			requirement |= REQUIREMENT_A_TCHF;
		break;
	case GSM48_CMODE_SPEECH_AMR:
		if (codec_type_is_supported(c->current.lchan->conn, GSM0808_SCT_FR3))
			requirement |= REQUIREMENT_A_TCHF;
		if (codec_type_is_supported(c->current.lchan->conn, GSM0808_SCT_HR3))
			requirement |= REQUIREMENT_A_TCHH;
		break;
	default:
		LOGPHOLCHAN(c->current.lchan, LOGL_DEBUG, "Not even considering: src is not a SPEECH mode lchan\n");
		/* FIXME: should allow handover of non-speech lchans */
		return;
	}

	if (!requirement) {
		LOGPHOLCHAN(c->current.lchan, LOGL_ERROR, "lchan doesn't fit its own requirements??\n");
		return;
	}

	/* Requirement B and C */

	/* We don't know how many timeslots are free in the remote BSS. We can only indicate that it
	 * would work out and hope for the best. */
	if (requirement & REQUIREMENT_A_TCHF)
		requirement |= REQUIREMENT_B_TCHF | REQUIREMENT_C_TCHF;
	if (requirement & REQUIREMENT_A_TCHH)
		requirement |= REQUIREMENT_B_TCHH | REQUIREMENT_C_TCHH;

	/* return mask of fulfilled requirements */
	c->requirements = requirement;
}

/* Trigger handover or assignment depending on the target BTS */
static int trigger_local_ho_or_as(struct ho_candidate *c, uint8_t requirements)
{
	struct handover_out_req req;
	int afs_bias = 0;
	bool full_rate = false;

	/* afs_bias becomes > 0, if AFS is used and is improved */
	if (c->current.lchan->tch_mode == GSM48_CMODE_SPEECH_AMR)
		afs_bias = ho_get_hodec2_afs_bias_rxlev(c->target.bts->ho);

	/* select TCH rate, prefer TCH/F if AFS is improved */
	switch (c->current.lchan->type) {
	case GSM_LCHAN_TCH_F:
		/* keep on full rate, if TCH/F is a candidate */
		if ((requirements & REQUIREMENT_TCHF_MASK)) {
			if (c->current.bts == c->target.bts) {
				LOGPHOLCHAN(c->current.lchan, LOGL_INFO, "Not performing assignment: Already on target type\n");
				return 0;
			}
			full_rate = true;
			break;
		}
		/* change to half rate */
		if (!(requirements & REQUIREMENT_TCHH_MASK)) {
			LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_ERROR,
					 "neither TCH/F nor TCH/H requested, aborting ho/as\n");
			return -EINVAL;
		}
		break;
	case GSM_LCHAN_TCH_H:
		/* change to full rate if AFS is improved and a candidate */
		if (afs_bias > 0 && (requirements & REQUIREMENT_TCHF_MASK)) {
			full_rate = true;
			break;
		}
		/* change to full rate if the only candidate */
		if ((requirements & REQUIREMENT_TCHF_MASK)
		    && !(requirements & REQUIREMENT_TCHH_MASK)) {
			full_rate = true;
			break;
		}
		/* keep on half rate */
		if (!(requirements & REQUIREMENT_TCHH_MASK)) {
			LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_ERROR,
					 "neither TCH/F nor TCH/H requested, aborting ho/as\n");
			return -EINVAL;
		}
		if (c->current.bts == c->target.bts) {
			LOGPHOLCHAN(c->current.lchan, LOGL_INFO, "Not performing assignment: Already on target type\n");
			return 0;
		}
		break;
	default:
		LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_ERROR, "c->current.lchan is neither TCH/F nor TCH/H, aborting ho/as\n");
		return -EINVAL;
	}

	/* trigger handover or assignment */
	if  (c->current.bts == c->target.bts)
		LOGPHOLCHAN(c->current.lchan, LOGL_NOTICE, "Triggering assignment to %s, due to %s\n",
			    full_rate ? "TCH/F" : "TCH/H",
			    ho_reason_name(global_ho_reason));
	else
		LOGPHOLCHANTOBTS(c->current.lchan, c->target.bts, LOGL_INFO,
				 "Triggering handover to %s, due to %s\n",
				 full_rate ? "TCH/F" : "TCH/H",
				 ho_reason_name(global_ho_reason));

	req = (struct handover_out_req){
		.from_hodec_id = HODEC2,
		.old_lchan = c->current.lchan,
		.target_nik = *bts_ident_key(c->target.bts),
		.new_lchan_type = full_rate? GSM_LCHAN_TCH_F : GSM_LCHAN_TCH_H,
	};
	handover_request(&req);
	return 0;
}

static int trigger_remote_bss_ho(struct ho_candidate *c, uint8_t requirements)
{
	struct handover_out_req req;

	LOGPHOLCHANTOREMOTE(c->current.lchan, c->target.cil, LOGL_INFO,
			    "Triggering inter-BSC handover, due to %s\n",
			    ho_reason_name(global_ho_reason));

	req = (struct handover_out_req){
		.from_hodec_id = HODEC2,
		.old_lchan = c->current.lchan,
		.target_nik = c->target.nik,
	};
	handover_request(&req);
	return 0;
}

static int trigger_ho(struct ho_candidate *c, uint8_t requirements)
{
	if (c->target.bts)
		return trigger_local_ho_or_as(c, requirements);
	else
		return trigger_remote_bss_ho(c, requirements);
}

#define REQUIREMENTS_FMT "[%s%s%s]%s"
#define REQUIREMENTS_ARGS(REQUIREMENTS, TCHX) \
	     (REQUIREMENTS) & REQUIREMENT_A_TCH##TCHX ? "A" : \
		((REQUIREMENTS) & REQUIREMENT_TCH##TCHX##_MASK) == 0? "-" : "", \
	     (REQUIREMENTS) & REQUIREMENT_B_TCH##TCHX ? "B" : "", \
	     (REQUIREMENTS) & REQUIREMENT_C_TCH##TCHX ? "C" : "", \
	     ((REQUIREMENTS) & REQUIREMENT_TCH##TCHX##_MASK) == 0 ? " not a candidate" : \
	       (((REQUIREMENTS) & REQUIREMENT_TCH##TCHX##_MASK) == REQUIREMENT_A_TCH##TCHX ? \
	        " more congestion" : \
		((REQUIREMENTS) & REQUIREMENT_B_TCH##TCHX ? \
		 " good" : \
		  /* now has to be (REQUIREMENTS) & REQUIREMENT_C_TCHX != 0: */ \
		  " less-or-equal congestion"))

/* verbosely log about a handover candidate */
static inline void debug_candidate(struct ho_candidate *candidate)
{
#define HO_CANDIDATE_FMT(tchx, TCHX) "TCH/" #TCHX "={free %d (want %d), " REQUIREMENTS_FMT "}"
#define HO_CANDIDATE_ARGS(tchx, TCHX) \
	     candidate->target.free_tch##tchx, candidate->target.min_free_tch##tchx, \
	     REQUIREMENTS_ARGS(candidate->requirements, TCHX)

	if (!candidate->target.bts && !candidate->target.cil)
		LOGPHOLCHAN(candidate->current.lchan, LOGL_DEBUG, "Empty candidate\n");
	if (candidate->target.bts && candidate->target.cil)
		LOGPHOLCHAN(candidate->current.lchan, LOGL_ERROR, "Invalid candidate: both local- and remote-BSS target\n");

	if (candidate->target.cil)
		LOGPHOLCHANTOREMOTE(candidate->current.lchan, candidate->target.cil, LOGL_DEBUG,
				    "RX level %d dBm -> %d dBm\n",
				    rxlev2dbm(candidate->current.rxlev), rxlev2dbm(candidate->target.rxlev));

	if (candidate->target.bts == candidate->current.bts)
		LOGPHOLCHANTOBTS(candidate->current.lchan, candidate->target.bts, LOGL_DEBUG,
		     "RX level %d dBm; "
		     HO_CANDIDATE_FMT(f, F) "; " HO_CANDIDATE_FMT(h, H) "\n",
		     rxlev2dbm(candidate->current.rxlev),
		     HO_CANDIDATE_ARGS(f, F), HO_CANDIDATE_ARGS(h, H));
	else if (candidate->target.bts)
		LOGPHOLCHANTOBTS(candidate->current.lchan, candidate->target.bts, LOGL_DEBUG,
		     "RX level %d dBm -> %d dBm; "
		     HO_CANDIDATE_FMT(f, F) "; " HO_CANDIDATE_FMT(h, H) "\n",
		     rxlev2dbm(candidate->current.rxlev), rxlev2dbm(candidate->target.rxlev),
		     HO_CANDIDATE_ARGS(f, F), HO_CANDIDATE_ARGS(h, H));
}

static void candidate_set_free_tch(struct ho_candidate *c)
{
	struct gsm_lchan *next_lchan;

	c->current.free_tchf = bts_count_free_ts(c->current.bts, GSM_PCHAN_TCH_F);
	c->current.min_free_tchf = ho_get_hodec2_tchf_min_slots(c->current.bts->ho);
	c->current.free_tchh = bts_count_free_ts(c->current.bts, GSM_PCHAN_TCH_H);
	c->current.min_free_tchh = ho_get_hodec2_tchh_min_slots(c->current.bts->ho);
	switch (c->current.lchan->ts->pchan_is) {
	case GSM_PCHAN_TCH_F:
		c->current.free_tch = c->current.free_tchf;
		c->current.min_free_tch = c->current.min_free_tchf;
		c->current.lchan_frees_tchf = 1;
		if (c->current.lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_TCH_H_PDCH)
			c->current.lchan_frees_tchh = 2;
		else
			c->current.lchan_frees_tchh = 0;
		break;
	case GSM_PCHAN_TCH_H:
		c->current.free_tch = c->current.free_tchh;
		c->current.min_free_tch = c->current.min_free_tchh;
		c->current.lchan_frees_tchh = 1;
		/* Freeing one of two TCH/H does not free a dyn TS and would not free a TCH/F. It has to be the last
		 * TCH/H of a dynamic timeslot that is freed to get a new TCH/F in the current cell from the handover.
		 * Hence the ts_usage_count() condition. */
		if (c->current.lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_TCH_H_PDCH
		    && ts_usage_count(c->current.lchan->ts) == 1)
			c->current.lchan_frees_tchf = 1;
		else
			c->current.lchan_frees_tchf = 0;
		break;
	default:
		break;
	}

	c->target.free_tchf = bts_count_free_ts(c->target.bts, GSM_PCHAN_TCH_F);
	c->target.min_free_tchf = ho_get_hodec2_tchf_min_slots(c->target.bts->ho);
	c->target.free_tchh = bts_count_free_ts(c->target.bts, GSM_PCHAN_TCH_H);
	c->target.min_free_tchh = ho_get_hodec2_tchh_min_slots(c->target.bts->ho);

	/* Would the next TCH/F lchan occupy a dynamic timeslot that currently counts for free TCH/H timeslots? */
	next_lchan = lchan_avail_by_type(c->target.bts, GSM_LCHAN_TCH_F, false);
	if (next_lchan && next_lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_TCH_H_PDCH)
		c->target.next_tchf_reduces_tchh = 2;
	else
		c->target.next_tchf_reduces_tchh = 0;

	/* Would the next TCH/H lchan occupy a dynamic timeslot that currently counts for free TCH/F timeslots?
	 * Note that a dyn TS already in TCH/H mode (half occupied) would not reduce free TCH/F. */
	next_lchan = lchan_avail_by_type(c->target.bts, GSM_LCHAN_TCH_H, false);
	if (next_lchan && next_lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_TCH_H_PDCH
	    && next_lchan->ts->pchan_is != GSM_PCHAN_TCH_H)
		c->target.next_tchh_reduces_tchf = 1;
	else
		c->target.next_tchh_reduces_tchf = 0;
}

/* add candidate for re-assignment within the current cell */
static void collect_assignment_candidate(struct gsm_lchan *lchan, struct ho_candidate *clist,
					 unsigned int *candidates, int rxlev_current)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct ho_candidate c;

	c = (struct ho_candidate){
		.current = {
			.lchan = lchan,
			.bts = bts,
			.rxlev = rxlev_current,
		},
		.target = {
			.bts = bts,
			.rxlev = rxlev_current, /* same cell, same rxlev */
		},
	};
	candidate_set_free_tch(&c);
	check_requirements(&c);

	debug_candidate(&c);

	if (!c.requirements)
		return;

	clist[*candidates] = c;
	(*candidates)++;
}

/* add candidates for handover to all neighbor cells */
static void collect_handover_candidate(struct gsm_lchan *lchan, struct neigh_meas_proc *nmp,
				       struct ho_candidate *clist, unsigned int *candidates,
				       bool include_weaker_rxlev, int rxlev_current,
				       int *neighbors_count)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct gsm_bts *neighbor_bts;
	const struct gsm0808_cell_id_list2 *neighbor_cil;
	struct neighbor_ident_key ni = {
		.from_bts = bts->nr,
		.arfcn = nmp->arfcn,
		.bsic = nmp->bsic,
	};
	struct ho_candidate c;
	int min_rxlev;
	struct handover_cfg *neigh_cfg;

	/* skip empty slots */
	if (nmp->arfcn == 0)
		return;

	if (neighbors_count)
		(*neighbors_count)++;

	/* skip if measurement report is old */
	if (nmp->last_seen_nr != lchan->meas_rep_last_seen_nr) {
		LOGPHOLCHAN(lchan, LOGL_DEBUG, "neighbor ARFCN %u BSIC %u measurement report is old"
			    " (nmp->last_seen_nr=%u lchan->meas_rep_last_seen_nr=%u)\n",
			    nmp->arfcn, nmp->bsic, nmp->last_seen_nr, lchan->meas_rep_last_seen_nr);
		return;
	}

	find_handover_target_cell(&neighbor_bts, &neighbor_cil,
				  lchan->conn, &ni, false);

	if (!neighbor_bts && !neighbor_cil) {
		LOGPHOBTS(bts, LOGL_DEBUG, "no neighbor ARFCN %u BSIC %u configured for this cell\n",
			  nmp->arfcn, nmp->bsic);
		return;
	}

	/* in case we have measurements of our bts, due to misconfiguration */
	if (neighbor_bts == bts) {
		LOGPHOBTS(bts, LOGL_ERROR, "Configuration error: this BTS appears as its own neighbor\n");
		return;
	}

	/* For cells in a remote BSS, we cannot query the target cell's handover config, and hence
	 * instead assume the local BTS' config to apply. */
	neigh_cfg = (neighbor_bts ? : bts)->ho;

	c = (struct ho_candidate){
		.current = {
			.lchan = lchan,
			.bts = bts,
			.rxlev = rxlev_current,
		},
		.target = {
			.nik = ni,
			.bts = neighbor_bts,
			.cil = neighbor_cil,
			.rxlev = neigh_meas_avg(nmp, ho_get_hodec2_rxlev_neigh_avg_win(bts->ho)),
		},
	};
	candidate_set_free_tch(&c);

	/* Heed rxlev hysteresis only if the RXLEV/RXQUAL/TA levels of the MS aren't critically bad and
	 * we're just looking for an improvement. If levels are critical, we desperately need a handover
	 * and thus skip the hysteresis check. */
	if (!include_weaker_rxlev) {
		int pwr_hyst = ho_get_hodec2_pwr_hysteresis(bts->ho);
		if ((c.target.rxlev - c.current.rxlev) <= pwr_hyst) {
			LOGPHOCAND(&c, LOGL_DEBUG,
				   "Not a candidate, because RX level (%d dBm) is lower"
				   " or equal than current RX level (%d dBm) + hysteresis (%d)\n",
				   rxlev2dbm(c.target.rxlev), rxlev2dbm(c.current.rxlev), pwr_hyst);
			return;
		}
	}

	/* if the minimum level is not reached.
	 * In case of a remote-BSS, use the current BTS' configuration. */
	min_rxlev = ho_get_hodec2_min_rxlev(neigh_cfg);
	if (rxlev2dbm(c.target.rxlev) < min_rxlev) {
		LOGPHOCAND(&c, LOGL_DEBUG,
			   "Not a candidate, because RX level (%d dBm) is lower"
			   " than the minimum required RX level (%d dBm)\n",
			   rxlev2dbm(c.target.rxlev), min_rxlev);
		return;
	}

	if (neighbor_bts) {
		check_requirements(&c);
	} else
		check_requirements_remote_bss(&c);

	debug_candidate(&c);

	if (!c.requirements)
		return;

	clist[*candidates] = c;
	(*candidates)++;
}

static void collect_candidates_for_lchan(struct gsm_lchan *lchan,
					 struct ho_candidate *clist, unsigned int *candidates,
					 int *_rxlev_current, bool include_weaker_rxlev)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	int rxlev_current;
	bool assignment;
	bool handover;
	int neighbors_count = 0;

	OSMO_ASSERT(candidates);

	rxlev_current = current_rxlev(lchan);
	if (_rxlev_current)
		*_rxlev_current = rxlev_current;

	/* in case there is no measurement report (yet) */
	if (rxlev_current < 0) {
		LOGPHOLCHAN(lchan, LOGL_DEBUG, "Not collecting candidates, not enough measurements"
			    " (got %d, want %u)\n",
			    lchan->meas_rep_count, ho_get_hodec2_rxlev_avg_win(bts->ho));
		return;
	}

	assignment = ho_get_hodec2_as_active(bts->ho);
	handover = ho_get_ho_active(bts->ho);

	if (assignment)
		collect_assignment_candidate(lchan, clist, candidates, rxlev_current);

	if (handover) {
		int i;
		for (i = 0; i < ARRAY_SIZE(lchan->neigh_meas); i++) {
			collect_handover_candidate(lchan, &lchan->neigh_meas[i],
						   clist, candidates,
						   include_weaker_rxlev, rxlev_current, &neighbors_count);
		}
	}
}

/*
 * Search for a alternative / better cell.
 *
 * Do not trigger handover/assignment on slots which have already ongoing
 * handover/assignment processes. If no AFS improvement offset is given, try to
 * maintain the same TCH rate, if available.
 * Do not perform this process, if handover and assignment are disabled for
 * the current cell.
 * Do not perform handover, if the minimum acceptable RX level
 * is not reached for this cell.
 *
 * If one or more 'better cells' are available, check the current and neighbor
 * cell measurements in descending order of their RX levels (down-link):
 *
 *  * Select the best candidate that fulfills requirement B (no congestion
 *    after handover/assignment) and trigger handover or assignment.
 *  * If no candidate fulfills requirement B, select the best candidate that
 *    fulfills requirement C (less or equally congested cells after handover)
 *    and trigger handover or assignment.
 *  * If no candidate fulfills requirement C, do not perform handover nor
 *    assignment.
 *
 * If the RX level (down-link) or RX quality (down-link) of the current cell is
 * below minimum acceptable level, or if the maximum allowed timing advance is
 * reached or exceeded, check the RX levels (down-link) of the current and
 * neighbor cells in descending order of their levels: (bad BTS case)
 *
 *  * Select the best candidate that fulfills requirement B (no congestion after
 *    handover/assignment) and trigger handover or assignment.
 *  * If no candidate fulfills requirement B, select the best candidate that
 *    fulfills requirement C (less or equally congested cells after handover)
 *    and trigger handover or assignment.
 *  * If no candidate fulfills requirement C, select the best candidate that
 *    fulfills requirement A (ignore congestion after handover or assignment)
 *    and trigger handover or assignment.
 *  * If no candidate fulfills requirement A, do not perform handover nor
 *    assignment.
 *
 * RX levels (down-link) of current and neighbor cells:
 *
 *  * The RX levels of the current cell and neighbor cells are improved by a
 *    given offset, if AFS (AMR on TCH/F) is used or is a candidate for
 *    handover/assignment.
 *  * If AMR is used, the requirement for handover is checked for TCH/F and
 *    TCH/H. Both results (if any) are used as a candidate.
 *  * If AMR is used, the requirement for assignment to a different TCH slot
 *    rate is checked. The result (if available) is used as a candidate.
 *
 * If minimum RXLEV, minimum RXQUAL or maximum TA are exceeded, the caller should pass
 * include_weaker_rxlev=true so that handover is performed despite congestion.
 */
static int find_alternative_lchan(struct gsm_lchan *lchan, bool include_weaker_rxlev)
{
    return 0;
	struct gsm_bts *bts = lchan->ts->trx->bts;
	int ahs = (lchan->tch_mode == GSM48_CMODE_SPEECH_AMR
		   && lchan->type == GSM_LCHAN_TCH_H);
	int rxlev_current;
	struct ho_candidate clist[1 + ARRAY_SIZE(lchan->neigh_meas)];
	unsigned int candidates = 0;
	int i;
	struct ho_candidate *best_cand = NULL;
	unsigned int best_better_db;
	bool best_applied_afs_bias = false;
	int better;

	/* check for disabled handover/assignment at the current cell */
	if (!ho_get_hodec2_as_active(bts->ho)
	    && !ho_get_ho_active(bts->ho)) {
		LOGP(DHODEC, LOGL_INFO, "Skipping, Handover and Assignment both disabled in this cell\n");
		return 0;
	}

	collect_candidates_for_lchan(lchan, clist, &candidates, &rxlev_current, include_weaker_rxlev);

	/* If assignment is disabled and no neighbor cell report exists, or no neighbor cell qualifies,
	 * we may not even have any candidates. */
	if (!candidates) {
		LOGPHOLCHAN(lchan, LOGL_INFO, "No viable neighbor cells found\n");
		return 0;
	}

	/* select best candidate that fulfills requirement B: no congestion after HO.
	 * Exclude remote-BSS neighbors: to avoid oscillation between neighboring BSS,
	 * rather keep subscribers in the local BSS unless there is critical RXLEV/TA. */
	best_better_db = 0;
	for (i = 0; i < candidates; i++) {
		int afs_bias;
		if (!(clist[i].requirements & REQUIREMENT_B_MASK))
			continue;

		/* Only consider Local-BSS cells */
		if (!clist[i].target.bts)
			continue;

		better = clist[i].target.rxlev - clist[i].current.rxlev;
		/* Apply AFS bias? */
		afs_bias = 0;
		if (ahs && (clist[i].requirements & REQUIREMENT_B_TCHF))
			afs_bias = ho_get_hodec2_afs_bias_rxlev(clist[i].target.bts->ho);
		better += afs_bias;
		if (better > best_better_db) {
			best_cand = &clist[i];
			best_better_db = better;
			best_applied_afs_bias = afs_bias? true : false;
		}
	}

	/* perform handover, if there is a candidate */
	if (best_cand) {
		LOGPHOCAND(best_cand, LOGL_INFO, "Best candidate, RX level %d%s\n",
			   rxlev2dbm(best_cand->target.rxlev),
			   best_applied_afs_bias ? " (applied AHS -> AFS rxlev bias)" : "");
		return trigger_ho(best_cand, best_cand->requirements & REQUIREMENT_B_MASK);
	}

	/* select best candidate that fulfills requirement C: less or equal congestion after HO,
	 * again excluding remote-BSS neighbors. */
	best_better_db = 0;
	for (i = 0; i < candidates; i++) {
		int afs_bias;
		if (!(clist[i].requirements & REQUIREMENT_C_MASK))
			continue;

		/* Only consider Local-BSS cells */
		if (!clist[i].target.bts)
			continue;

		better = clist[i].target.rxlev - clist[i].current.rxlev;
		/* Apply AFS bias? */
		afs_bias = 0;
		if (ahs && (clist[i].requirements & REQUIREMENT_C_TCHF))
			afs_bias = ho_get_hodec2_afs_bias_rxlev(clist[i].target.bts->ho);
		better += afs_bias;
		if (better > best_better_db) {
			best_cand = &clist[i];
			best_better_db = better;
			best_applied_afs_bias = afs_bias? true : false;
		}
	}

	/* perform handover, if there is a candidate */
	if (best_cand) {
		LOGPHOCAND(best_cand, LOGL_INFO, "Best candidate, RX level %d%s\n",
			   rxlev2dbm(best_cand->target.rxlev),
			   best_applied_afs_bias? " (applied AHS -> AFS rxlev bias)" : "");
		return trigger_ho(best_cand, best_cand->requirements & REQUIREMENT_C_MASK);
	}

	/* we are done in case the MS RXLEV/RXQUAL/TA aren't critical and we're avoiding congestion. */
	if (!include_weaker_rxlev) {
		LOGPHOLCHAN(lchan, LOGL_INFO, "No better/less congested neighbor cell found\n");
		return 0;
	}

	/* Select best candidate that fulfills requirement A: can service the call.
	 * From above we know that there are no options that avoid congestion. Here we're trying to find
	 * *any* free lchan that has no critically low RXLEV and is able to handle the MS.
	 * We're also prepared to handover to remote BSS. */
	best_better_db = 0;
	for (i = 0; i < candidates; i++) {
		int afs_bias;
		if (!(clist[i].requirements & REQUIREMENT_A_MASK))
			continue;

		better = clist[i].target.rxlev - clist[i].current.rxlev;
		/* Apply AFS bias?
		 * (never to remote-BSS neighbors, since we will not change the lchan type for those.) */
		afs_bias = 0;
		if (ahs && (clist[i].requirements & REQUIREMENT_A_TCHF)
		    && clist[i].target.bts)
			afs_bias = ho_get_hodec2_afs_bias_rxlev(clist[i].target.bts->ho);
		better += afs_bias;
		if (better > best_better_db) {
			best_cand = &clist[i];
			best_better_db = better;
			best_applied_afs_bias = afs_bias? true : false;
		}
	}

	/* perform handover, if there is a candidate */
	if (best_cand) {
		LOGPHOCAND(best_cand, LOGL_INFO, "Best candidate: RX level %d%s\n",
			   rxlev2dbm(best_cand->target.rxlev),
			   best_applied_afs_bias ? " (applied AHS -> AFS rxlev bias)" : "");
		return trigger_ho(best_cand, best_cand->requirements & REQUIREMENT_A_MASK);
	}

	/* Damn, all is congested, has too low RXLEV or cannot service the voice call due to codec
	 * restrictions or because all lchans are taken. */
	LOGPHOLCHAN(lchan, LOGL_INFO, "No alternative lchan found\n");
	return 0;
}

/*
 * Handover/assignment check, if measurement report is received
 *
 * Do not trigger handover/assignment on slots which have already ongoing
 * handover/assignment processes.
 *
 * In case of handover triggered because maximum allowed timing advance is
 * exceeded, the handover penalty timer is started for the originating cell.
 *
 */
static void on_measurement_report(struct gsm_meas_rep *mr)
{
	struct gsm_lchan *lchan = mr->lchan;
	struct gsm_bts *bts = lchan->ts->trx->bts;
	int av_rxlev = -EINVAL, av_rxqual = -EINVAL;
	unsigned int pwr_interval;

	/* we currently only do handover for TCH channels */

	LOGPHOLCHAN(lchan, LOGL_NOTICE, "MEASUREMENT REPORT for %s channel (%d neighbors)\n",
		gsm_chan_t_name(lchan->type), mr->num_cell);
		for (int i = 0; i < mr->num_cell; i++) {
			struct gsm_meas_rep_cell *mrc = &mr->cell[i];
			LOGPHOLCHAN(lchan, LOGL_NOTICE,
				"  %d: arfcn=%u bsic=%u neigh_idx=%u rxlev=%d flags=%x\n",
				i, mrc->arfcn, mrc->bsic, mrc->neigh_idx, rxlev2dbm(mrc->rxlev), mrc->flags);
		}
	if(&mr->ul && &mr->ul.full)
		LOGPHOLCHAN(lchan, LOGL_NOTICE, "UL (full): rxlev=%d, rxqual=%d\n", rxlev2dbm(mr->ul.full.rx_lev), mr->ul.full.rx_qual);
	if(&mr->dl && &mr->dl.full)
		LOGPHOLCHAN(lchan, LOGL_NOTICE, "DL (full): rxlev=%d, rxqual=%d\n", rxlev2dbm(mr->dl.full.rx_lev), mr->dl.full.rx_qual);

	switch (mr->lchan->type) {
	case GSM_LCHAN_TCH_F:
	case GSM_LCHAN_TCH_H:
		break;
	default:
		return;
	}


	/* parse actual neighbor cell info */
	if (mr->num_cell > 0 && mr->num_cell < 7)
		process_meas_neigh(mr);

	// don't handover here
	return;

	/* check for ongoing handover/assignment */
	if (!lchan->conn) {
		LOGPHOLCHAN(lchan, LOGL_ERROR, "Skipping, No subscriber connection???\n");
		return;
	}
	if (lchan->conn->assignment.new_lchan) {
		LOGPHOLCHAN(lchan, LOGL_INFO, "Skipping, Initial Assignment is still ongoing\n");
		return;
	}
	if (lchan->conn->ho.fi) {
		LOGPHOLCHAN(lchan, LOGL_INFO, "Skipping, Handover still ongoing\n");
		return;
	}

	/* get average levels. if not enough measurements yet, value is < 0 */
	av_rxlev = get_meas_rep_avg(lchan,
				    ho_get_hodec2_full_tdma(bts->ho) ?
				    MEAS_REP_DL_RXLEV_FULL : MEAS_REP_DL_RXLEV_SUB,
				    ho_get_hodec2_rxlev_avg_win(bts->ho));
	av_rxqual = get_meas_rep_avg(lchan,
				     ho_get_hodec2_full_tdma(bts->ho) ?
				     MEAS_REP_DL_RXQUAL_FULL : MEAS_REP_DL_RXQUAL_SUB,
				     ho_get_hodec2_rxqual_avg_win(bts->ho));
	if (av_rxlev < 0 && av_rxqual < 0) {
		LOGPHOLCHAN(lchan, LOGL_INFO, "Skipping, Not enough recent measurements\n");
		return;
	}

	/* improve levels in case of AFS, if defined */
	if (lchan->type == GSM_LCHAN_TCH_F
	 && lchan->tch_mode == GSM48_CMODE_SPEECH_AMR) {
		int av_rxlev_was = av_rxlev;
		int av_rxqual_was = av_rxqual;
		int rxlev_bias = ho_get_hodec2_afs_bias_rxlev(bts->ho);
		int rxqual_bias = ho_get_hodec2_afs_bias_rxqual(bts->ho);
		if (av_rxlev >= 0)
			av_rxlev = av_rxlev + rxlev_bias;
		if (av_rxqual >= 0)
			av_rxqual = OSMO_MAX(0, av_rxqual - rxqual_bias);

		LOGPHOLCHAN(lchan, LOGL_DEBUG,
			    "Avg RX level = %d dBm, %+d dBm AFS bias = %d dBm;"
			    " Avg RX quality = %d%s, %+d AFS bias = %d\n",
			    rxlev2dbm(av_rxlev_was), rxlev_bias, rxlev2dbm(av_rxlev),
			    OSMO_MAX(-1, av_rxqual_was), av_rxqual_was < 0 ? " (invalid)" : "",
			    -rxqual_bias, OSMO_MAX(-1, av_rxqual));
	} else {
		LOGPHOLCHAN(lchan, LOGL_DEBUG, "Avg RX level = %d dBm; Avg RX quality = %d%s\n",
			    rxlev2dbm(av_rxlev),
			    OSMO_MAX(-1, av_rxqual), av_rxqual < 0 ? " (invalid)" : "");
	}

	/* Bad Quality */
	if (av_rxqual >= 0 && av_rxqual > ho_get_hodec2_min_rxqual(bts->ho)) {
		if (rxlev2dbm(av_rxlev) > -85) {
			global_ho_reason = HO_REASON_INTERFERENCE;
			LOGPHOLCHAN(lchan, LOGL_INFO, "Trying handover/assignment"
				    " due to interference (bad quality)\n");
		} else {
			global_ho_reason = HO_REASON_BAD_QUALITY;
			LOGPHOLCHAN(lchan, LOGL_INFO, "Trying handover/assignment due to bad quality\n");
		}
		find_alternative_lchan(lchan, true);
		return;
	}

	/* Low Level */
	if (av_rxlev >= 0 && rxlev2dbm(av_rxlev) < ho_get_hodec2_min_rxlev(bts->ho)) {
		global_ho_reason = HO_REASON_LOW_RXLEVEL;
		LOGPHOLCHAN(lchan, LOGL_NOTICE, "RX level is TOO LOW: %d < %d\n",
			    rxlev2dbm(av_rxlev), ho_get_hodec2_min_rxlev(bts->ho));
		find_alternative_lchan(lchan, true);
		return;
	}

	/* Max Distance */
	if (lchan->meas_rep_count > 0
	    && lchan->last_ta > ho_get_hodec2_max_distance(bts->ho)) {
		global_ho_reason = HO_REASON_MAX_DISTANCE;
		LOGPHOLCHAN(lchan, LOGL_NOTICE, "TA is TOO HIGH: %u > %d\n",
			    lchan->last_ta, ho_get_hodec2_max_distance(bts->ho));
		/* start penalty timer to prevent coming back too
		 * early. it must be started before selecting a better cell,
		 * so there is no assignment selected, due to running
		 * penalty timer. */
		bts_penalty_time_add(lchan->conn, bts, ho_get_hodec2_penalty_max_dist(bts->ho));
		find_alternative_lchan(lchan, true);
		return;
	}

	/* pwr_interval's range is 1-99, clarifying that no div-zero shall happen in modulo below: */
	pwr_interval = ho_get_hodec2_pwr_interval(bts->ho);
	OSMO_ASSERT(pwr_interval);

	/* try handover to a better cell */
	if (av_rxlev >= 0 && (mr->nr % pwr_interval) == 0) {
		global_ho_reason = HO_REASON_BETTER_CELL;
		find_alternative_lchan(lchan, false);
	}
}

static bool lchan_is_on_dynamic_ts(struct gsm_lchan *lchan)
{
	return lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_TCH_H_PDCH
		|| lchan->ts->pchan_on_init == GSM_PCHAN_TCH_F_PDCH;
}

static bool is_upgrade_to_tchf(const struct ho_candidate *c, uint8_t for_requirement)
{
	return c->current.lchan
		&& (c->current.lchan->type == GSM_LCHAN_TCH_H)
		&& ((c->requirements & for_requirement) & (REQUIREMENT_B_TCHF | REQUIREMENT_C_TCHF));
}

/* Given two candidates, pick the one that should rather be moved during handover.
 * Return the better candidate in out-parameters best_cand and best_avg_db.
 */
static struct ho_candidate *pick_better_lchan_to_move(struct ho_candidate *a,
						      struct ho_candidate *b,
						      uint8_t for_requirement)
{
	int a_rxlev_change;
	int b_rxlev_change;
	struct ho_candidate *ret = a;

	if (!a)
		return b;
	if (!b)
		return a;

	a_rxlev_change = a->target.rxlev - a->current.rxlev;
	b_rxlev_change = b->target.rxlev - b->current.rxlev;

	/* Typically, a congestion related handover reduces RXLEV. If there is a candidate that actually improves RXLEV,
	 * prefer that, because it pre-empts a likely handover due to measurement results later.  Also favor unchanged
	 * RXLEV over a loss of RXLEV (favor staying within the same cell over moving to a worse cell). */
	if (a_rxlev_change >= 0 && a_rxlev_change > b_rxlev_change)
		return a;
	if (b_rxlev_change >= 0 && b_rxlev_change > a_rxlev_change)
		return b;

	if (a_rxlev_change < 0 && b_rxlev_change < 0) {
		/* For handover that reduces RXLEV, favor the highest resulting RXLEV, AFS bias applied. */
		int a_rxlev = a->target.rxlev + a->target.rxlev_afs_bias;
		int b_rxlev = b->target.rxlev + b->target.rxlev_afs_bias;

		if (a_rxlev > b_rxlev)
			return a;
		if (b_rxlev > a_rxlev)
			return b;
		/* There is no target RXLEV difference between the two candidates. Let other factors influence the
		 * choice. */
	}

	/* Prefer picking a dynamic timeslot: free PDCH and allow more timeslot type flexibility for further
	 * congestion resolution. */
	if (lchan_is_on_dynamic_ts(b->current.lchan)) {
		unsigned int ac, bc;

		if (!lchan_is_on_dynamic_ts(a->current.lchan))
			return b;

		/* Both are dynamic timeslots. Prefer one that completely (or to a higher degree) frees its
		 * timeslot. */
		ac = ts_usage_count(a->current.lchan->ts);
		bc = ts_usage_count(b->current.lchan->ts);
		if (bc < ac)
			return b;
		if (ac < bc)
			return a;
		/* (If both are dynamic timeslots, favor moving the later dynamic timeslot. That is a vague preference
		 * for later dynamic TS to become PDCH and join up with plain PDCH that follow it -- not actually clear
		 * whether that helps, and depends on user's TS config. No harm done either way.) */
		ret = b;
	}

	/* When upgrading TCH/H to TCH/F, favor moving a TCH/H with lower current rxlev, because presumably that
	 * one benefits more from a higher bandwidth. */
	if (is_upgrade_to_tchf(a, for_requirement) && is_upgrade_to_tchf(b, for_requirement)) {
		if (b->current.rxlev < a->current.rxlev)
			return b;
		if (a->current.rxlev < b->current.rxlev)
			return a;
	}

	return ret;
}

static struct ho_candidate *pick_best_candidate(struct ho_candidate *clist, int clist_len,
						uint8_t for_requirement)
{
	struct ho_candidate *result = NULL;
	int i;

	for (i = 0; i < clist_len; i++) {
		struct ho_candidate *c = &clist[i];

		/* For multiple passes of congestion resolution, already handovered candidates are marked by lchan =
		 * NULL. (though at the time of writing, multiple passes of congestion resolution are DISABLED.) */
		if (!c->current.lchan)
			continue;

		/* Omit remote BSS */
		if (!c->target.bts)
			continue;

		if (!(c->requirements & for_requirement))
			continue;

		/* improve AHS */
		if (is_upgrade_to_tchf(c, for_requirement))
			c->target.rxlev_afs_bias = ho_get_hodec2_afs_bias_rxlev(c->target.bts->ho);
		else
			c->target.rxlev_afs_bias = 0;

		result = pick_better_lchan_to_move(result, c, for_requirement);
	}

	return result;
}

/*
 * Handover/assignment check after timer timeout:
 *
 * Even if handover process tries to prevent a congestion, a cell might get
 * congested due to new call setups or handovers to prevent loss of radio link.
 * A cell is congested, if not the minimum number of free slots are available.
 * The minimum number can be defined for TCH/F and TCH/H individually.
 *
 * Do not perform congestion check, if no minimum free slots are defined for
 * a cell.
 * Do not trigger handover/assignment on slots which have already ongoing
 * handover/assignment processes. If no AFS improvement offset is given, try to
 * maintain the same TCH rate, if available.
 * Do not perform this process, if handover and assignment are disabled for
 * the current cell.
 * Do not perform handover, if the minimum acceptable RX level
 * is not reached for this cell.
 * Only check candidates that will solve/reduce congestion.
 *
 * If a cell is congested, all slots are checked for all their RX levels
 * (down-link) of the current and neighbor cell measurements in descending
 * order of their RX levels:
 *
 *  * Select the best candidate that fulfills requirement B (no congestion after
 *    handover/assignment), trigger handover or assignment. Candidates that will
 *    cause an assignment from AHS (AMR on TCH/H) to AFS (AMR on TCH/F) are
 *    omitted.
 *     o This process repeated until the minimum required number of free slots
 *       are restored or if all cell measurements are checked. The process ends
 *       then, otherwise:
 *  * Select the worst candidate that fulfills requirement B, trigger
 *    assignment. Note that only assignment candidates for changing from AHS to
 *    AFS are left.
 *     o This process repeated until the minimum required number of free slots
 *       are restored or if all cell measurements are checked. The process ends
 *       then, otherwise:
 *  * Select the best candidates that fulfill requirement C (less or equally
 *    congested cells after handover/assignment), trigger handover or
 *    assignment. Candidates that will cause an assignment from AHS (AMR on
 *    TCH/H) to AFS (AMR on TCH/F) are omitted.
 *     o This process repeated until the minimum required number of free slots
 *       are restored or if all cell measurements are checked. The process ends
 *       then, otherwise:
 *  * Select the worst candidate that fulfills requirement C, trigger
 *    assignment. Note that only assignment candidates for changing from AHS to
 *    AFS are left.
 *     o This process repeated until the minimum required number of free slots
 *       are restored or if all cell measurements are checked.
 */
static int bts_resolve_congestion(struct gsm_bts *bts, int tchf_congestion, int tchh_congestion)
{
	struct gsm_lchan *lc;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	int i, j;
	struct ho_candidate *clist;
	unsigned int candidates;
	struct ho_candidate *best_cand = NULL;
	int rc = 0;
	int any_ho = 0;

	if (tchf_congestion < 0)
		tchf_congestion = 0;
	if (tchh_congestion < 0)
		tchh_congestion = 0;

	LOGPHOBTS(bts, LOGL_INFO, "congested: %d TCH/F and %d TCH/H should be moved\n",
		  tchf_congestion, tchh_congestion);

	/* allocate array of all bts */
	clist = talloc_zero_array(tall_bsc_ctx, struct ho_candidate,
		bts->num_trx * 8 * 2 * (1 + ARRAY_SIZE(lc->neigh_meas)));
	if (!clist)
		return 0;

	candidates = 0;

	/* loop through all active lchan and collect candidates */
	llist_for_each_entry(trx, &bts->trx_list, list) {
		if (!trx_is_usable(trx))
			continue;

		for (i = 0; i < 8; i++) {
			ts = &trx->ts[i];
			if (!ts_is_usable(ts))
				continue;

			/* (Do not consider dynamic TS that are in PDCH mode) */
			switch (ts->pchan_is) {
			case GSM_PCHAN_TCH_F:
				/* No need to collect TCH/F candidates if no TCH/F needs to be moved. */
				if (tchf_congestion == 0)
					continue;

				lc = &ts->lchan[0];
				/* omit if channel not active */
				if (lc->type != GSM_LCHAN_TCH_F
				    || !lchan_state_is(lc, LCHAN_ST_ESTABLISHED))
					break;
				/* omit if there is an ongoing ho/as */
				if (!lc->conn || lc->conn->assignment.new_lchan
				    || lc->conn->ho.fi)
					break;
				/* We desperately want to resolve congestion, ignore rxlev when
				 * collecting candidates by passing include_weaker_rxlev=true. */
				collect_candidates_for_lchan(lc, clist, &candidates, NULL, true);
				break;
			case GSM_PCHAN_TCH_H:
				/* No need to collect TCH/H candidates if no TCH/H needs to be moved. */
				if (tchh_congestion == 0)
					continue;

				for (j = 0; j < 2; j++) {
					lc = &ts->lchan[j];
					/* omit if channel not active */
					if (lc->type != GSM_LCHAN_TCH_H
					    || !lchan_state_is(lc, LCHAN_ST_ESTABLISHED))
						continue;
					/* omit of there is an ongoing ho/as */
					if (!lc->conn
					    || lc->conn->assignment.new_lchan
					    || lc->conn->ho.fi)
						continue;
					/* We desperately want to resolve congestion, ignore rxlev when
					 * collecting candidates by passing include_weaker_rxlev=true. */
					collect_candidates_for_lchan(lc, clist, &candidates, NULL, true);
				}
				break;
			default:
				break;
			}
		}
	}

	if (!candidates) {
		LOGPHOBTS(bts, LOGL_DEBUG, "No neighbor cells qualify to solve congestion\n");
		goto exit;
	}
	if (log_check_level(DHODEC, LOGL_DEBUG)) {
		LOGPHOBTS(bts, LOGL_DEBUG, "Considering %u candidates to solve congestion:\n", candidates);
		for (i = 0; i < candidates; i++) {

			LOGPHOCAND(&clist[i], LOGL_DEBUG, "#%d: req={TCH/F:" REQUIREMENTS_FMT ", TCH/H:" REQUIREMENTS_FMT "} avg-rxlev=%d dBm\n",
				   i, REQUIREMENTS_ARGS(clist[i].requirements, F),
				   REQUIREMENTS_ARGS(clist[i].requirements, H),
				   rxlev2dbm(clist[i].target.rxlev));
		}
	}

#if 0
next_b1:
#endif
	/* select best candidate that does not cause congestion in the target.
	 * Do not resolve congestion towards remote BSS, which would cause oscillation if the remote BSS is also
	 * congested.
	 * Treating specially below: upgrading TCH/H to TCH/F within the same cell, so omit here.
	 */
	/* TODO: attempt inter-BSC HO if no local cells qualify, and rely on the remote BSS to
	 * deny receiving the handover if it also considers itself congested. Maybe do that only
	 * when the cell is absolutely full, i.e. not only min-free-slots. (x) */
	best_cand = pick_best_candidate(clist, candidates, REQUIREMENT_B_MASK);
	if (best_cand) {
		any_ho = 1;
		LOGPHOCAND(best_cand, LOGL_DEBUG, "Best candidate: RX level %d%s\n",
			   rxlev2dbm(best_cand->target.rxlev),
			   best_cand->target.rxlev_afs_bias ? " (applied AHS->AFS bias)" : "");
		trigger_ho(best_cand, best_cand->requirements & REQUIREMENT_B_MASK);
#if 0
		/* if there is still congestion, mark lchan as deleted
		 * and redo this process */
		if (best_cand->lchan->type == GSM_LCHAN_TCH_H)
			tchh_congestion--;
		else
			tchf_congestion--;
		if (tchf_congestion > 0 || tchh_congestion > 0) {
			delete_lchan = best_cand->lchan;
			best_cand = NULL;
			goto next_b1;
		}
#else
		/* must exit here, because triggering handover/assignment
		 * will cause change in requirements. more check for this
		 * bts is performed in the next iteration.
		 */
#endif
		goto exit;
	}

#if 0
next_c1:
#endif
	/* Select best candidate that balances congestion.
	 * Again no remote BSS.
	 * Again no TCH/H -> F upgrades within the same cell. */
	best_cand = pick_best_candidate(clist, candidates, REQUIREMENT_C_MASK);
	if (best_cand) {
		any_ho = 1;
		LOGPHOCAND(best_cand, LOGL_INFO, "Best candidate: RX level %d%s\n",
			   rxlev2dbm(best_cand->target.rxlev),
			   best_cand->target.rxlev_afs_bias ? " (applied AHS -> AFS rxlev bias)" : "");
		trigger_ho(best_cand, best_cand->requirements & REQUIREMENT_C_MASK);
#if 0
		/* if there is still congestion, mark lchan as deleted
		 * and redo this process */
		if (best_cand->lchan->type == GSM_LCHAN_TCH_H)
			tchh_congestion--;
		else
			tchf_congestion--;
		if (tchf_congestion > 0 || tchh_congestion > 0) {
			delete_lchan = best_cand->lchan;
			best_cand = NULL;
			goto next_c1;
		}
#else
		/* must exit here, because triggering handover/assignment
		 * will cause change in requirements. more check for this
		 * bts is performed in the next iteration.
		 */
#endif
		goto exit;
	}

	LOGPHOBTS(bts, LOGL_DEBUG, "Did not find a best candidate that fulfills requirement C\n");

exit:
	/* free array */
	talloc_free(clist);

	if (tchf_congestion <= 0 && tchh_congestion <= 0)
		LOGP(DHODEC, LOGL_INFO, "Congestion at BTS %d solved!\n",
			bts->nr);
	else if (any_ho)
		LOGP(DHODEC, LOGL_INFO, "Congestion at BTS %d reduced!\n",
			bts->nr);
	else
		LOGP(DHODEC, LOGL_INFO, "Congestion at BTS %d can't be reduced/solved!\n", bts->nr);

	return rc;
}

static void bts_congestion_check(struct gsm_bts *bts)
{
	int min_free_tchf, min_free_tchh;
	int free_tchf, free_tchh;

	global_ho_reason = HO_REASON_CONGESTION;

	/* only check BTS if TRX 0 is usable */
	if (!trx_is_usable(bts->c0)) {
		LOGPHOBTS(bts, LOGL_DEBUG, "No congestion check: TRX 0 not usable\n");
		return;
	}

	/* only check BTS if handover or assignment is enabled */
	if (!ho_get_hodec2_as_active(bts->ho)
	    && !ho_get_ho_active(bts->ho)) {
		LOGPHOBTS(bts, LOGL_DEBUG, "No congestion check: Assignment and Handover both disabled\n");
		return;
	}

	min_free_tchf = ho_get_hodec2_tchf_min_slots(bts->ho);
	min_free_tchh = ho_get_hodec2_tchh_min_slots(bts->ho);

	/* only check BTS with congestion level set */
	if (!min_free_tchf && !min_free_tchh) {
		LOGPHOBTS(bts, LOGL_DEBUG, "No congestion check: no minimum for free TCH/F nor TCH/H set\n");
		return;
	}

	free_tchf = bts_count_free_ts(bts, GSM_PCHAN_TCH_F);
	free_tchh = bts_count_free_ts(bts, GSM_PCHAN_TCH_H);
	LOGPHOBTS(bts, LOGL_INFO, "Congestion check: (free/want-free) TCH/F=%d/%d TCH/H=%d/%d\n",
		  free_tchf, min_free_tchf, free_tchh, min_free_tchh);

	/* only check BTS if congested */
	if (free_tchf >= min_free_tchf && free_tchh >= min_free_tchh) {
		LOGPHOBTS(bts, LOGL_DEBUG, "Not congested\n");
		return;
	}

	LOGPHOBTS(bts, LOGL_DEBUG, "Attempting to resolve congestion...\n");
	bts_resolve_congestion(bts, min_free_tchf - free_tchf, min_free_tchh - free_tchh);
}

void hodec2_congestion_check(struct gsm_network *net)
{
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list)
		bts_congestion_check(bts);
}

static void force_handover(struct gsm_network *net);

static void congestion_check_cb(void *arg)
{
	struct gsm_network *net = arg;
	force_handover(net);
	//hodec2_congestion_check(net);
	reinit_congestion_timer(net);
}

static void on_handover_end(struct gsm_subscriber_connection *conn, enum handover_result result)
{
	struct gsm_bts *old_bts = NULL;
	struct gsm_bts *new_bts = NULL;
	int penalty;
	struct handover *ho = &conn->ho;

	/* If all went fine, then there are no penalty timers to set. */
	if (result == HO_RESULT_OK)
		return;

	if (conn->lchan)
		old_bts = conn->lchan->ts->trx->bts;
	if (ho->new_lchan)
		new_bts = ho->new_lchan->ts->trx->bts;

	/* Only interested in handovers within this BSS or going out into another BSS. Incoming handovers
	 * from another BSS are accounted for in the other BSS. */
	if (!old_bts)
		return;

	if (conn->hodec2.failures < ho_get_hodec2_retries(old_bts->ho)) {
		conn->hodec2.failures++;
		LOG_HO(conn, LOGL_NOTICE, "Failed, allowing handover decision to try again"
		       " (%d/%d attempts)\n",
		       conn->hodec2.failures, ho_get_hodec2_retries(old_bts->ho));
		return;
	}

	switch (ho->scope) {
	case HO_INTRA_CELL:
		penalty = ho_get_hodec2_penalty_failed_as(old_bts->ho);
		break;
	default:
		/* TODO: separate penalty for inter-BSC HO? */
		penalty = ho_get_hodec2_penalty_failed_ho(old_bts->ho);
		break;
	}

	LOG_HO(conn, LOGL_NOTICE, "Failed, starting penalty timer (%d s)\n", penalty);
	conn->hodec2.failures = 0;

	if (new_bts)
		bts_penalty_time_add(conn, new_bts, penalty);
	else
		nik_penalty_time_add(conn, &ho->target_cell, penalty);
}

static struct handover_decision_callbacks hodec2_callbacks = {
	.hodec_id = 2,
	.on_measurement_report = on_measurement_report,
	.on_handover_end = on_handover_end,
};

void hodec2_init(struct gsm_network *net)
{
	handover_decision_callbacks_register(&hodec2_callbacks);
	hodec2_initialized = true;
	reinit_congestion_timer(net);
}


// my strange code

static int handover_from_to(struct gsm_bts *from_bts, struct gsm_bts *to_bts, int count, enum gsm_chan_t chan_type) {
	LOGP(DHODEC, LOGL_NOTICE, "Handover from %u to %u %d calls\n", from_bts->c0->arfcn, to_bts->c0->arfcn, count);

	struct gsm_bts_trx *trx;

	llist_for_each_entry(trx, &from_bts->trx_list, list) {
		int i;
		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			if(count <= 0)
				return count;
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			struct gsm_lchan *lchan;

			if (ts->fi->state != TS_ST_IN_USE)
				continue;

			ts_for_each_lchan(lchan, ts) {

				/* omit if channel not active */
				if (lchan->type != chan_type || !lchan_state_is(lchan, LCHAN_ST_ESTABLISHED))
					continue;
				/* omit if there is an ongoing ho/as */
				if (!lchan->conn || lchan->conn->assignment.new_lchan
					|| lchan->conn->ho.fi)
					continue;


				struct handover_out_req req = {
					.from_hodec_id = HODEC_USER,
					.old_lchan = lchan,
					.target_nik = *bts_ident_key(to_bts),
				};

				handover_request(&req);
				count --;
			}
		}
	}

	return count;
}

static int get_ho_as_channels_count(struct gsm_bts *bts, enum gsm_phys_chan_config pchan) {
	struct gsm_bts_trx *trx;
	int count = 0;
	llist_for_each_entry(trx, &bts->trx_list, list) {
		int i;
		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			struct gsm_lchan *lchan;

			if (ts->pchan_is != pchan)
				continue;

			ts_for_each_lchan(lchan, ts) {
				/* omit if there is an ongoing ho/as */
				if (lchan->conn && (lchan->conn->assignment.new_lchan
					|| lchan->conn->ho.fi))
					count++;
			}
		}
	}
	return count;
}

static int get_voice_channels_count(struct gsm_bts *bts, enum gsm_phys_chan_config pchan) {
	struct gsm_bts_trx *trx;
	int count = 0;
	llist_for_each_entry(trx, &bts->trx_list, list) {
		int i;
		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			struct gsm_lchan *lchan;

			if (ts->pchan_is != pchan)
				continue;

			ts_for_each_lchan(lchan, ts)
				count++;
		}
	}
	return count;
}

static void force_handover(struct gsm_network *net) {

	if(net->ho_count <= 0)
		return;

	struct gsm_bts *bts;

	struct gsm_bts *bts_0;
	struct gsm_bts *bts_1;


	// find valid bts

	unsigned int bts_valid_count = 0;
	llist_for_each_entry(bts, &net->bts_list, list) {
		if(trx_is_usable(bts->c0)) {
			if(bts_valid_count == 0)
				bts_0 = bts;
			else
				bts_1 = bts;

			bts_valid_count++;
		}
	}


	// 2 valid bts only 
	if(bts_valid_count != 2)
		return;

	int all_slots_0 = get_voice_channels_count(bts_0, GSM_PCHAN_TCH_F) + get_voice_channels_count(bts_0, GSM_PCHAN_TCH_H);
	int all_slots_1 = get_voice_channels_count(bts_1, GSM_PCHAN_TCH_F) + get_voice_channels_count(bts_1, GSM_PCHAN_TCH_H);


	if(all_slots_0 == 0 || all_slots_1 == 0)
		return;

	int free_slots_0 = bts_count_free_ts(bts_0, GSM_PCHAN_TCH_F) + bts_count_free_ts(bts_0, GSM_PCHAN_TCH_H);
	int free_slots_1 = bts_count_free_ts(bts_1, GSM_PCHAN_TCH_F) + bts_count_free_ts(bts_1, GSM_PCHAN_TCH_H);

	int used_slots_0 = all_slots_0 - free_slots_0;
	int used_slots_1 = all_slots_1 - free_slots_1;

	int ho_count_0 = get_ho_as_channels_count(bts_0, GSM_PCHAN_TCH_F) + get_ho_as_channels_count(bts_0, GSM_PCHAN_TCH_H);
	int ho_count_1 = get_ho_as_channels_count(bts_1, GSM_PCHAN_TCH_F) + get_ho_as_channels_count(bts_1, GSM_PCHAN_TCH_H);

	int max_hangover_batch_count = net->ho_count;


	if(used_slots_0 > used_slots_1) {
		// Force handover 0->1
		LOGP(DHODEC, LOGL_NOTICE, "Handover info: bts0(all=%d, free=%d, used=%d, ho=%d), bts1(all=%d, free=%d, used=%d, ho=%d)\n",
			all_slots_0, free_slots_0, used_slots_0, ho_count_0, all_slots_1, free_slots_1, used_slots_1, ho_count_1);
		int calls_count = OSMO_MIN(all_slots_0 - ho_count_0, free_slots_1 - 1);
		calls_count = OSMO_MIN(max_hangover_batch_count - ho_count_0, calls_count);
		if(calls_count > 0) {
		    int left_calls_count = handover_from_to(bts_0, bts_1, calls_count, GSM_LCHAN_TCH_F);
		    left_calls_count = handover_from_to(bts_0, bts_1, left_calls_count, GSM_LCHAN_TCH_H);
		    net->ho_count = net->ho_count - (calls_count - left_calls_count);
		    LOGP(DHODEC, LOGL_NOTICE, "Force handover 0->1, try %d calls, left %d calls\n", calls_count, left_calls_count);
		}
	}
	else if(used_slots_1 > used_slots_0) {
		// Force handover 1->0
		LOGP(DHODEC, LOGL_NOTICE, "Handover info: bts0(all=%d, free=%d, used=%d, ho=%d), bts1(all=%d, free=%d, used=%d, ho=%d)\n",
			all_slots_0, free_slots_0, used_slots_0, ho_count_0, all_slots_1, free_slots_1, used_slots_1, ho_count_1);
		int calls_count = OSMO_MIN(all_slots_1 - ho_count_1, free_slots_0 - 1);
		calls_count = OSMO_MIN(max_hangover_batch_count - ho_count_1, calls_count);
		if(calls_count > 0) {
		    int left_calls_count = handover_from_to(bts_1, bts_0, calls_count, GSM_LCHAN_TCH_F);
		    left_calls_count = handover_from_to(bts_1, bts_0, left_calls_count, GSM_LCHAN_TCH_H);
		    net->ho_count = net->ho_count - (calls_count - left_calls_count);
		    LOGP(DHODEC, LOGL_NOTICE, "Force handover 1->0, try %d calls, left %d calls\n", calls_count, left_calls_count);
		}
	}
}
