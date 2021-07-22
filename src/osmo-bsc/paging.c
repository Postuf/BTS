/* Paging helper and manager.... */
/* (C) 2009,2013 by Holger Hans Peter Freyther <zecke@selfish.org>
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

/*
 * Relevant specs:
 *     12.21:
 *       - 9.4.12 for CCCH Local Threshold
 *
 *     05.58:
 *       - 8.5.2 CCCH Load indication
 *       - 9.3.15 Paging Load
 *
 * Approach:
 *       - Send paging command to subscriber
 *       - On Channel Request we will remember the reason
 *       - After the ACK we will request the identity
 *	 - Then we will send assign the gsm_subscriber and
 *	 - and call a callback
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/tdef.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm0502.h>

#include <osmocom/bsc/bsc_subscriber.h>
#include <osmocom/bsc/paging.h>
#include <osmocom/bsc/debug.h>
#include <osmocom/bsc/signal.h>
#include <osmocom/bsc/abis_rsl.h>
#include <osmocom/bsc/gsm_data.h>
#include <osmocom/bsc/chan_alloc.h>
#include <osmocom/bsc/gsm_08_08.h>
#include <osmocom/bsc/gsm_04_08_rr.h>
#include <osmocom/bsc/bsc_subscr_conn_fsm.h>
#include <osmocom/bsc/bts.h>

void *tall_paging_ctx = NULL;

#define PAGING_TIMER 0, 10000

/*
 * Kill one paging request update the internal list...
 */
static void paging_remove_request(struct gsm_bts_paging_state *paging_bts,
				  struct gsm_paging_request *to_be_deleted)
{
	osmo_timer_del(&to_be_deleted->T3113);
	llist_del(&to_be_deleted->entry);
	bsc_subscr_put(to_be_deleted->bsub, BSUB_USE_PAGING_REQUEST);
	talloc_free(to_be_deleted);
}

static void page_ms(struct gsm_paging_request *request)
{
	unsigned int page_group;
	struct gsm_bts *bts = request->bts;
	struct osmo_mobile_identity mi;

	log_set_context(LOG_CTX_BSC_SUBSCR, request->bsub);

	LOG_BTS(bts, DPAG, LOGL_INFO, "Going to send paging commands: %s"
		" for ch. type %d (attempt %d)\n", bsc_subscr_name(request->bsub),
		request->chan_type, request->attempts);

	if (request->bsub->tmsi == GSM_RESERVED_TMSI) {
		mi = (struct osmo_mobile_identity){
			.type = GSM_MI_TYPE_IMSI,
		};
		OSMO_STRLCPY_ARRAY(mi.imsi, request->bsub->imsi);
	} else {
		mi = (struct osmo_mobile_identity){
			.type = GSM_MI_TYPE_TMSI,
			.tmsi = request->bsub->tmsi,
		};
	}

	page_group = gsm0502_calc_paging_group(&bts->si_common.chan_desc,
					       str_to_imsi(request->bsub->imsi));
	rsl_paging_cmd(bts, page_group, &mi, request->chan_type, false);
	log_set_context(LOG_CTX_BSC_SUBSCR, NULL);
}

static void paging_schedule_if_needed(struct gsm_bts_paging_state *paging_bts)
{
	if (llist_empty(&paging_bts->pending_requests))
		return;

	if (!osmo_timer_pending(&paging_bts->work_timer))
		osmo_timer_schedule(&paging_bts->work_timer, PAGING_TIMER);
}


static void paging_handle_pending_requests(struct gsm_bts_paging_state *paging_bts);
static void paging_give_credit(void *data)
{
	struct gsm_bts_paging_state *paging_bts = data;

	LOG_BTS(paging_bts->bts, DPAG, LOGL_NOTICE, "No PCH LOAD IND, adding 20 slots)\n");
	paging_bts->available_slots = 20;
	paging_handle_pending_requests(paging_bts);
}

/*! count the number of free channels for given RSL channel type required
 * \param[in] BTS on which we shall count
 * \param[in] rsl_type the RSL channel needed type
 * \returns number of free channels matching \a rsl_type in \a bts */
static int can_send_pag_req(struct gsm_bts *bts, int rsl_type)
{
	struct pchan_load pl;
	int count;

	memset(&pl, 0, sizeof(pl));
	bts_chan_load(&pl, bts);

	switch (rsl_type) {
	case RSL_CHANNEED_TCH_F:
	case RSL_CHANNEED_TCH_ForH:
		goto count_tch;
		break;
	case RSL_CHANNEED_SDCCH:
		goto count_sdcch;
		break;
	case RSL_CHANNEED_ANY:
	default:
		if (bts->network->pag_any_tch)
			goto count_tch;
		else
			goto count_sdcch;
		break;
	}

	return 0;

	/* could available SDCCH */
count_sdcch:
	count = 0;
	count += pl.pchan[GSM_PCHAN_SDCCH8_SACCH8C].total
			- pl.pchan[GSM_PCHAN_SDCCH8_SACCH8C].used;
	count += pl.pchan[GSM_PCHAN_CCCH_SDCCH4].total
			- pl.pchan[GSM_PCHAN_CCCH_SDCCH4].used;
	return bts->paging.free_chans_need > count;

count_tch:
	count = 0;
	count += pl.pchan[GSM_PCHAN_TCH_F].total
			- pl.pchan[GSM_PCHAN_TCH_F].used;
	if (bts->network->neci)
		count += pl.pchan[GSM_PCHAN_TCH_H].total
				- pl.pchan[GSM_PCHAN_TCH_H].used;
	return bts->paging.free_chans_need > count;
}

/*
 * This is kicked by the periodic PAGING LOAD Indicator
 * coming from abis_rsl.c
 *
 * We attempt to iterate once over the list of items but
 * only upto available_slots.
 */
static void paging_handle_pending_requests(struct gsm_bts_paging_state *paging_bts)
{
	struct gsm_paging_request *request = NULL;

	/*
	 * Determine if the pending_requests list is empty and
	 * return then.
	 */
	if (llist_empty(&paging_bts->pending_requests)) {
		/* since the list is empty, no need to reschedule the timer */
		return;
	}

	/*
	 * In case the BTS does not provide us with load indication and we
	 * ran out of slots, call an autofill routine. It might be that the
	 * BTS did not like our paging messages and then we have counted down
	 * to zero and we do not get any messages.
	 */
	if (paging_bts->available_slots == 0) {
		osmo_timer_setup(&paging_bts->credit_timer, paging_give_credit,
				 paging_bts);
		osmo_timer_schedule(&paging_bts->credit_timer, 5, 0);
		return;
	}

	request = llist_entry(paging_bts->pending_requests.next,
			      struct gsm_paging_request, entry);

	/* we need to determine the number of free channels */
	if (paging_bts->free_chans_need != -1) {
		if (can_send_pag_req(request->bts, request->chan_type) != 0)
			goto skip_paging;
	}

	/* Skip paging if the bts is down. */
	if (!request->bts->oml_link)
		goto skip_paging;

	/* handle the paging request now */
	page_ms(request);
	paging_bts->available_slots--;
	request->attempts++;

	/* take the current and add it to the back */
	llist_del(&request->entry);
	llist_add_tail(&request->entry, &paging_bts->pending_requests);

skip_paging:
	osmo_timer_schedule(&paging_bts->work_timer, PAGING_TIMER);
}

static void paging_worker(void *data)
{
	struct gsm_bts_paging_state *paging_bts = data;

	paging_handle_pending_requests(paging_bts);
}

/*! initialize the bts paging state, if it hasn't been initialized yet */
static void paging_init_if_needed(struct gsm_bts *bts)
{
	if (bts->paging.bts)
		return;

	bts->paging.bts = bts;

	/* This should be initialized only once. There is currently no code that sets bts->paging.bts
	 * back to NULL, so let's just assert this one instead of graceful handling. */
	OSMO_ASSERT(llist_empty(&bts->paging.pending_requests));

	osmo_timer_setup(&bts->paging.work_timer, paging_worker,
			 &bts->paging);

	/* Large number, until we get a proper message */
	bts->paging.available_slots = 20;
}

/*! do we have any pending paging requests for given subscriber? */
static int paging_pending_request(struct gsm_bts_paging_state *bts,
				  struct bsc_subscr *bsub)
{
	struct gsm_paging_request *req;

	llist_for_each_entry(req, &bts->pending_requests, entry) {
		if (bsub == req->bsub)
			return 1;
	}

	return 0;
}

/*! Call-back once T3113 (paging timeout) expires for given paging_request */
static void paging_T3113_expired(void *data)
{
	struct gsm_paging_request *req = (struct gsm_paging_request *)data;

	log_set_context(LOG_CTX_BSC_SUBSCR, req->bsub);

	LOGP(DPAG, LOGL_INFO, "T3113 expired for request %p (%s)\n",
	     req, bsc_subscr_name(req->bsub));

	/* must be destroyed before calling cbfn, to prevent double free */
	rate_ctr_inc(&req->bts->bts_ctrs->ctr[BTS_CTR_PAGING_EXPIRED]);

	/* destroy it now. Do not access req afterwards */
	paging_remove_request(&req->bts->paging, req);

	log_set_context(LOG_CTX_BSC_SUBSCR, NULL);
}

#define GSM_FRAME_DURATION_us	4615
#define GSM51_MFRAME_DURATION_us (51 * GSM_FRAME_DURATION_us) /* 235365 us */
static unsigned int calculate_timer_3113(struct gsm_bts *bts)
{
	unsigned int to_us, to;
	struct osmo_tdef *d = osmo_tdef_get_entry(bts->network->T_defs, 3113);

	/* Note: d should always contain a valid pointer since all timers,
	 * including 3113 are statically pre-defined in
	 * struct osmo_tdef gsm_network_T_defs. */
	OSMO_ASSERT(d);

	if (!bts->T3113_dynamic)
		return d->val;

	/* TODO: take into account load of paging group for req->bsub */

	/* MFRMS defines repeat interval of paging messages for MSs that belong
	 * to same paging group across multiple 51 frame multiframes.
	 * MAXTRANS defines maximum number of RACH retransmissions.
	 */
	to_us = GSM51_MFRAME_DURATION_us * (bts->si_common.chan_desc.bs_pa_mfrms + 2) *
		bts->si_common.rach_control.max_trans;

	/* ceiling in seconds + extra time */
	to = (to_us + 999999) / 1000000 + d->val;
	LOG_BTS(bts, DPAG, LOGL_DEBUG, "Paging request: T3113 expires in %u seconds\n", to);
	return to;
}

/*! Start paging + paging timer for given subscriber on given BTS
 * \param bts BTS on which to page
 * \param[in] bsub subscriber we want to page
 * \param[in] type type of radio channel we're requirign
 * \param[in] msc MSC which has issue this paging
 * \returns 0 on success, negative on error */
static int _paging_request(const struct bsc_paging_params *params, struct gsm_bts *bts)
{
	struct gsm_bts_paging_state *bts_entry = &bts->paging;
	struct gsm_paging_request *req;
	unsigned int t3113_timeout_s;

	rate_ctr_inc(&bts->bts_ctrs->ctr[BTS_CTR_PAGING_ATTEMPTED]);

	if (paging_pending_request(bts_entry, params->bsub)) {
		LOG_PAGING_BTS(params, bts, DPAG, LOGL_INFO, "Paging request already pending for this subscriber\n");
		rate_ctr_inc(&bts->bts_ctrs->ctr[BTS_CTR_PAGING_ALREADY]);
		return -EEXIST;
	}

	LOG_PAGING_BTS(params, bts, DPAG, LOGL_DEBUG, "Start paging\n");
	req = talloc_zero(tall_paging_ctx, struct gsm_paging_request);
	OSMO_ASSERT(req);
	req->reason = params->reason;
	req->bsub = params->bsub;
	bsc_subscr_get(req->bsub, BSUB_USE_PAGING_REQUEST);
	req->bts = bts;
	req->chan_type = params->chan_needed;
	req->msc = params->msc;
	osmo_timer_setup(&req->T3113, paging_T3113_expired, req);
	t3113_timeout_s = calculate_timer_3113(bts);
	osmo_timer_schedule(&req->T3113, t3113_timeout_s, 0);
	llist_add_tail(&req->entry, &bts_entry->pending_requests);
	paging_schedule_if_needed(bts_entry);

	return 0;
}

/*! Handle PAGING request from MSC for one (matching) BTS
 * \param bts BTS on which to page
 * \param[in] bsub subscriber we want to page
 * \param[in] type type of radio channel we're requirign
 * \param[in] msc MSC which has issue this paging
 * returns 1 on success; 0 in case of error (e.g. TRX down) */
int paging_request_bts(const struct bsc_paging_params *params, struct gsm_bts *bts)
{
	int rc;

	/* skip all currently inactive TRX */
	if (!trx_is_usable(bts->c0))
		return 0;

	/* maybe it is the first time we use it */
	paging_init_if_needed(bts);

	/* Trigger paging, pass any error to the caller */
	rc = _paging_request(params, bts);
	if (rc < 0)
		return 0;
	return 1;
}

/*! Stop paging a given subscriber on a given BTS.
 * \param[out] returns the MSC that paged the subscriber, if any.
 * \param[out] returns the reason for a pending paging, if any.
 * \param[in] bts BTS which has received a paging response.
 * \param[in] bsub subscriber.
 * \returns number of pending pagings.
 */
static int paging_request_stop_bts(struct bsc_msc_data **msc_p, enum bsc_paging_reason *reason_p,
				   struct gsm_bts *bts, struct bsc_subscr *bsub)
{
	struct gsm_bts_paging_state *bts_entry = &bts->paging;
	struct gsm_paging_request *req, *req2;

	*msc_p = NULL;
	*reason_p = BSC_PAGING_NONE;

	paging_init_if_needed(bts);

	llist_for_each_entry_safe(req, req2, &bts_entry->pending_requests,
				  entry) {
		if (req->bsub != bsub)
			continue;
		*msc_p = req->msc;
		*reason_p = req->reason;
		LOG_BTS(bts, DPAG, LOGL_DEBUG, "Stop paging %s\n", bsc_subscr_name(bsub));
		paging_remove_request(&bts->paging, req);
		return 1;
	}

	return 0;
}

/*! Stop paging on all cells and return the MSC that paged (if any) and all pending paging reasons.
 * \param[out] returns the MSC that paged the subscriber, if there was a pending request.
 * \param[out] returns the ORed bitmask of all reasons of pending pagings.
 * \param[in] bts BTS which has received a paging response
 * \param[in] bsub subscriber
 * \returns number of pending pagings.
 */
int paging_request_stop(struct bsc_msc_data **msc_p, enum bsc_paging_reason *reasons_p,
			struct gsm_bts *bts, struct bsc_subscr *bsub)
{
	struct gsm_bts *bts_i;
	struct bsc_msc_data *paged_from_msc;
	int count;
	enum bsc_paging_reason reasons;
	OSMO_ASSERT(bts);

	count = paging_request_stop_bts(&paged_from_msc, &reasons, bts, bsub);
	if (paged_from_msc) {
		count++;
		rate_ctr_inc(&bts->bts_ctrs->ctr[BTS_CTR_PAGING_RESPONDED]);
		rate_ctr_inc(&bts->network->bsc_ctrs->ctr[BSC_CTR_PAGING_RESPONDED]);
	}

	llist_for_each_entry(bts_i, &bsc_gsmnet->bts_list, list) {
		struct bsc_msc_data *paged_from_msc2;
		enum bsc_paging_reason reason2;
		count += paging_request_stop_bts(&paged_from_msc2, &reason2, bts_i, bsub);
		if (paged_from_msc2) {
			reasons |= reason2;
			if (!paged_from_msc) {
				/* If this happened, it would be a bit weird: it means there was no Paging Request
				 * pending on the BTS that sent the Paging Reponse, but there *is* a Paging Request
				 * pending on a different BTS. But why not return an MSC when we found one. */
				paged_from_msc = paged_from_msc2;
			}
		}
	}

	*msc_p = paged_from_msc;
	*reasons_p = reasons;

	return count;
}

/* Remove all paging requests, for specific reasons only. */
int paging_request_cancel(struct bsc_subscr *bsub, enum bsc_paging_reason reasons)
{
	struct gsm_bts *bts;
	int count = 0;

	llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
		struct gsm_paging_request *req, *req2;

		paging_init_if_needed(bts);

		llist_for_each_entry_safe(req, req2, &bts->paging.pending_requests, entry) {
			if (req->bsub != bsub)
				continue;
			if (!(req->reason & reasons))
				continue;
			LOG_BTS(bts, DPAG, LOGL_DEBUG, "Cancel paging %s\n", bsc_subscr_name(bsub));
			paging_remove_request(&bts->paging, req);
			count++;
		}
	}
	return count;
}

/*! Update the BTS paging buffer slots on given BTS */
void paging_update_buffer_space(struct gsm_bts *bts, uint16_t free_slots)
{
	paging_init_if_needed(bts);

	osmo_timer_del(&bts->paging.credit_timer);
	bts->paging.available_slots = free_slots;
	paging_schedule_if_needed(&bts->paging);
}

/*! Count the number of pending paging requests on given BTS */
unsigned int paging_pending_requests_nr(struct gsm_bts *bts)
{
	unsigned int requests = 0;
	struct gsm_paging_request *req;

	paging_init_if_needed(bts);

	llist_for_each_entry(req, &bts->paging.pending_requests, entry)
		++requests;

	return requests;
}

/*! Flush all paging requests at a given BTS for a given MSC (or NULL if all MSC should be flushed). */
void paging_flush_bts(struct gsm_bts *bts, struct bsc_msc_data *msc)
{
	struct gsm_paging_request *req, *req2;
	int num_cancelled = 0;

	paging_init_if_needed(bts);

	llist_for_each_entry_safe(req, req2, &bts->paging.pending_requests, entry) {
		if (msc && req->msc != msc)
			continue;
		/* now give up the data structure */
		LOG_BTS(bts, DPAG, LOGL_DEBUG, "Stop paging %s (flush)\n", bsc_subscr_name(req->bsub));
		paging_remove_request(&bts->paging, req);
		num_cancelled++;
	}

	rate_ctr_add(&bts->bts_ctrs->ctr[BTS_CTR_PAGING_MSC_FLUSH], num_cancelled);
}

/*! Flush all paging requests issued by \a msc on any BTS in \a net */
void paging_flush_network(struct gsm_network *net, struct bsc_msc_data *msc)
{
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list)
		paging_flush_bts(bts, msc);
}
