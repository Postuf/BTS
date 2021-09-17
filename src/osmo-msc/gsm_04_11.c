/* Point-to-Point (PP) Short Message Service (SMS)
 * Support on Mobile Radio Interface
 * 3GPP TS 04.11 version 7.1.0 Release 1998 / ETSI TS 100 942 V7.1.0 */

/* (C) 2008 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 * (C) 2011 by Andreas Eversberg <jolly@eversberg.eu>
 *
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>

#include "config.h"

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/gsm0411_utils.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>
#include <osmocom/gsm/protocol/gsm_03_40.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/db.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/db.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/msc_a.h>
#include <osmocom/msc/paging.h>

#ifdef BUILD_SMPP
#include "smpp_smsc.h"
#endif

void *tall_gsms_ctx;
static uint32_t new_callref = 0x40000001;

struct gsm_sms *sms_alloc(void)
{
	return talloc_zero(tall_gsms_ctx, struct gsm_sms);
}

void sms_free(struct gsm_sms *sms)
{
	/* drop references to subscriber structure */
	if (sms->receiver)
		vlr_subscr_put(sms->receiver, VSUB_USE_SMS_RECEIVER);
#ifdef BUILD_SMPP
	if (sms->smpp.esme)
		smpp_esme_put(sms->smpp.esme);
#endif

	talloc_free(sms);
}

struct gsm_sms *sms_from_text(struct vlr_subscr *receiver,
			      const char *sender_msisdn,
                              int dcs, const char *text)
{
	struct gsm_sms *sms = sms_alloc();

	if (!sms)
		return NULL;

	vlr_subscr_get(receiver, VSUB_USE_SMS_RECEIVER);
	sms->receiver = receiver;
	OSMO_STRLCPY_ARRAY(sms->text, text);

	OSMO_STRLCPY_ARRAY(sms->src.addr, sender_msisdn);
	sms->reply_path_req = 0;
	sms->status_rep_req = 0;
	sms->ud_hdr_ind = 0;
	sms->protocol_id = 0; /* implicit */
	sms->data_coding_scheme = dcs;
	OSMO_STRLCPY_ARRAY(sms->dst.addr, receiver->msisdn);
	/* Generate user_data */
	sms->user_data_len = gsm_7bit_encode_n(sms->user_data, sizeof(sms->user_data),
						sms->text, NULL);

	return sms;
}


static void send_signal(int sig_no,
			struct gsm_trans *trans,
			struct gsm_sms *sms,
			int paging_result)
{
	struct sms_signal_data sig;
	sig.trans = trans;
	sig.sms = sms;
	sig.paging_result = paging_result;
	osmo_signal_dispatch(SS_SMS, sig_no, &sig);
}

static int gsm411_sendmsg(struct gsm_trans *trans, struct msgb *msg)
{
	LOG_TRANS(trans, LOGL_DEBUG, "GSM4.11 TX %s\n", msgb_hexdump(msg));
	msg->l3h = msg->data;
	return msc_a_tx_dtap_to_i(trans->msc_a, msg);
}

/* Handle MMTS (More Messages to Send) indication */
static void gsm411_handle_mmts_ind(const struct gsm_trans *trans)
{
	int32_t use_count;

	OSMO_ASSERT(trans);
	OSMO_ASSERT(trans->msc_a);

	use_count = osmo_use_count_by(&trans->msc_a->use_count, MSC_A_USE_SMS_MMTS);
	OSMO_ASSERT(use_count >= 0); /* Shall not be negative */

	if (trans->sms.sm_rp_mmts_ind && use_count == 0) {
		LOG_TRANS(trans, LOGL_INFO, "Multi-part SMS delivery is initiated\n");
		msc_a_get(trans->msc_a, MSC_A_USE_SMS_MMTS);
	} else if (trans->sms.sm_rp_mmts_ind && use_count > 0) {
		LOG_TRANS(trans, LOGL_INFO, "Continuing multi-part SMS delivery\n");
	} else if (!trans->sms.sm_rp_mmts_ind && use_count > 0) {
		LOG_TRANS(trans, LOGL_INFO, "Multi-part SMS delivery has been completed\n");
		msc_a_put(trans->msc_a, MSC_A_USE_SMS_MMTS);
	}
}

/* Paging callback for MT SMS (Paging is triggered by SMC) */
static void mmsms_paging_cb(struct msc_a *msc_a, struct gsm_trans *trans)
{
	struct gsm_sms *sms = trans->sms.sms;

	LOG_TRANS(trans, LOGL_DEBUG, "%s(%s)\n", __func__, msc_a ? "success" : "expired");

	if (msc_a) {
		/* Paging succeeded */
		/* Associate transaction with established connection */
		msc_a_get(msc_a, MSC_A_USE_SMS);
		trans->msc_a = msc_a;

		/* Multi-part SMS: handle MMTS (More Messages to Send) indication */
		gsm411_handle_mmts_ind(trans);

		/* Confirm successful connection establishment */
		gsm411_smc_recv(&trans->sms.smc_inst, GSM411_MMSMS_EST_CNF, NULL, 0);
	} else {
		/* Paging expired or failed */
		/* Inform SMC about channel establishment failure */
		gsm411_smc_recv(&trans->sms.smc_inst, GSM411_MMSMS_REL_IND, NULL, 0);

		/* gsm411_send_rp_data() doesn't set trans->sms.sms */
		if (sms != NULL) {
			/* Notify the SMSqueue and free stored SMS */
			send_signal(S_SMS_UNKNOWN_ERROR, NULL, sms, 0);
			trans->sms.sms = NULL;
			sms_free(sms);
		}

		/* Destroy this transaction */
		trans_free(trans);
	}
}

static int gsm411_mmsms_est_req(struct gsm_trans *trans)
{
	/* Subscriber's data shall be associated */
	OSMO_ASSERT(trans->vsub != NULL);

	/* Check if connection is already established */
	if (trans->msc_a != NULL) {
		LOG_TRANS(trans, LOGL_DEBUG, "Using an existing connection\n");
		return gsm411_smc_recv(&trans->sms.smc_inst,
			GSM411_MMSMS_EST_CNF, NULL, 0);
	}

	/* Initiate Paging procedure */
	LOG_TRANS(trans, LOGL_DEBUG, "Initiating Paging due to MMSMS_EST_REQ\n");
	trans->paging_request = paging_request_start(trans->vsub, PAGING_CAUSE_SIGNALLING_LOW_PRIO,
						     mmsms_paging_cb, trans, "MT-SMS");
	if (!trans->paging_request) {
		LOG_TRANS(trans, LOGL_ERROR, "Failed to initiate Paging\n");
		/* Inform SMC about channel establishment failure */
		gsm411_smc_recv(&trans->sms.smc_inst, GSM411_MMSMS_REL_IND, NULL, 0);
		trans_free(trans);
		return -EIO;
	}

	return 0;
}

/* Prefix msg with a 04.08/04.11 CP header */
static int gsm411_cp_sendmsg(struct msgb *msg, struct gsm_trans *trans,
			     uint8_t msg_type)
{
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	/* Outgoing needs the highest bit set */
	gh->proto_discr = GSM48_PDISC_SMS | (trans->transaction_id<<4);
	gh->msg_type = msg_type;
	OMSC_LINKID_CB(msg) = trans->dlci;

	LOG_TRANS(trans, LOGL_DEBUG, "sending CP message (trans=%x)\n", trans->transaction_id);

	return gsm411_sendmsg(trans, msg);
}

/* mm_send: receive MMCCSMS sap message from SMC */
static int gsm411_mm_send(struct gsm411_smc_inst *inst, int msg_type,
			struct msgb *msg, int cp_msg_type)
{
	struct gsm_trans *trans =
		container_of(inst, struct gsm_trans, sms.smc_inst);
	int rc = 0;

	switch (msg_type) {
	case GSM411_MMSMS_EST_REQ:
		rc = gsm411_mmsms_est_req(trans);
		break;
	case GSM411_MMSMS_DATA_REQ:
		rc = gsm411_cp_sendmsg(msg, trans, cp_msg_type);
		return rc; /* gsm411_cp_sendmsg() takes msg ownership */
	case GSM411_MMSMS_REL_REQ:
		LOG_TRANS(trans, LOGL_DEBUG, "Got MMSMS_REL_REQ, destroying transaction.\n");
		trans_free(trans);
		break;
	default:
		LOG_TRANS(trans, LOGL_NOTICE, "Unhandled MMCCSMS msg 0x%x\n", msg_type);
		rc = -EINVAL;
	}

	msgb_free(msg);
	return rc;
}

/* mm_send: receive MNCCSMS sap message from SMR */
int gsm411_mn_send(struct gsm411_smr_inst *inst, int msg_type,
			struct msgb *msg)
{
	struct gsm_trans *trans =
		container_of(inst, struct gsm_trans, sms.smr_inst);

	/* forward to SMC */
	return gsm411_smc_send(&trans->sms.smc_inst, msg_type, msg);
}

static int gsm340_rx_sms_submit(struct gsm_trans *trans, struct gsm_sms *gsms)
{
	if (db_sms_store(gsms) != 0) {
		LOG_TRANS(trans, LOGL_ERROR, "Failed to store SMS in Database\n");
		return GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER;
	}
	/* dispatch a signal to tell higher level about it */
	send_signal(S_SMS_SUBMITTED, NULL, gsms, 0);

	return 0;
}

/* generate a TPDU address field compliant with 03.40 sec. 9.1.2.5 */
static int gsm340_gen_oa_sub(uint8_t *oa, unsigned int oa_len,
			 const struct gsm_sms_addr *src)
{
	/* network specific, private numbering plan */
	return gsm340_gen_oa(oa, oa_len, src->ton, src->npi, src->addr);
}

/* generate a msgb containing an 03.40 9.2.2.1 SMS-DELIVER TPDU derived from
 * struct gsm_sms, returns total size of TPDU */
static int gsm340_gen_sms_deliver_tpdu(struct gsm_trans *trans, struct msgb *msg, struct gsm_sms *sms)
{
	uint8_t *smsp;
	uint8_t oa[12];	/* max len per 03.40 */
	uint8_t octet_len;
	unsigned int old_msg_len = msg->len;
	int oa_len;

	/* generate first octet with masked bits */
	smsp = msgb_put(msg, 1);
	/* TP-MTI (message type indicator) */
	*smsp = GSM340_SMS_DELIVER_SC2MS;
	/* TP-MMS (more messages to send) */
	if (0 /* FIXME */)
		*smsp |= 0x04;
	/* TP-SRI(deliver)/SRR(submit) */
	if (sms->status_rep_req)
		*smsp |= 0x20;
	/* TP-UDHI (indicating TP-UD contains a header) */
	if (sms->ud_hdr_ind)
		*smsp |= 0x40;

	/* generate originator address */
	oa_len = gsm340_gen_oa_sub(oa, sizeof(oa), &sms->src);
	if (oa_len < 0)
		return -ENOSPC;

	smsp = msgb_put(msg, oa_len);
	memcpy(smsp, oa, oa_len);

	/* generate TP-PID */
	smsp = msgb_put(msg, 1);
	*smsp = sms->protocol_id;

	/* generate TP-DCS */
	smsp = msgb_put(msg, 1);
	*smsp = sms->data_coding_scheme;

	/* generate TP-SCTS */
	smsp = msgb_put(msg, 7);
	gsm340_gen_scts(smsp, time(NULL));

	/* generate TP-UDL */
	smsp = msgb_put(msg, 1);
	*smsp = sms->user_data_len;

	/* generate TP-UD */
	switch (gsm338_get_sms_alphabet(sms->data_coding_scheme)) {
	case DCS_7BIT_DEFAULT:
		octet_len = sms->user_data_len*7/8;
		if (sms->user_data_len*7%8 != 0)
			octet_len++;
		/* Warning, user_data_len indicates the amount of septets
		 * (characters), we need amount of octets occupied */
		smsp = msgb_put(msg, octet_len);
		memcpy(smsp, sms->user_data, octet_len);
		break;
	case DCS_UCS2:
	case DCS_8BIT_DATA:
		smsp = msgb_put(msg, sms->user_data_len);
		memcpy(smsp, sms->user_data, sms->user_data_len);
		break;
	default:
		LOG_TRANS(trans, LOGL_NOTICE, "Unhandled Data Coding Scheme: 0x%02X\n",
			  sms->data_coding_scheme);
		break;
	}

	return msg->len - old_msg_len;
}

/* As defined by GSM 03.40, Section 9.2.2.3. */
static int gsm340_gen_sms_status_report_tpdu(struct gsm_trans *trans, struct msgb *msg,
					     struct gsm_sms *sms)
{
	unsigned int old_msg_len = msg->len;
	uint8_t oa[12];	/* max len per 03.40 */
	uint8_t *smsp;
	int oa_len;

	/* generate first octet with masked bits */
	smsp = msgb_put(msg, 1);
	/* TP-MTI (message type indicator) */
	*smsp = GSM340_SMS_STATUS_REP_SC2MS;
	/* TP-MMS (more messages to send) */
	if (0 /* FIXME */)
		*smsp |= 0x04;
	/* TP-MR (message reference) */
	smsp = msgb_put(msg, 1);
	*smsp = sms->msg_ref;

	/* generate recipient address */
	oa_len = gsm340_gen_oa_sub(oa, sizeof(oa), &sms->src);
	if (oa_len < 0)
		return -ENOSPC;

	smsp = msgb_put(msg, oa_len);
	memcpy(smsp, oa, oa_len);

	/* generate TP-SCTS (Service centre timestamp) */
	smsp = msgb_put(msg, 7);
	gsm340_gen_scts(smsp, sms->created);

	/* generate TP-DT (Discharge time, in TP-SCTS format). */
	smsp = msgb_put(msg, 7);
	gsm340_gen_scts(smsp, sms->created);

	/* TP-ST (status) */
	smsp = msgb_put(msg, 1);
	/* From GSM 03.40, Section 9.2.3.15, 0x00 means OK. */
	*smsp = 0x00;

	LOG_TRANS(trans, LOGL_INFO, "sending status report for SMS reference %x\n",
		  sms->msg_ref);

	return msg->len - old_msg_len;
}

static int sms_route_mt_sms(struct gsm_trans *trans, struct gsm_sms *gsms)
{
	int rc;
	struct msc_a *msc_a = trans->msc_a;
	struct gsm_network *net = msc_a_net(msc_a);

#ifdef BUILD_SMPP
	/*
	 * Route through SMPP first before going to the local database. In case
	 * of a unroutable message and no local subscriber, SMPP will be tried
	 * twice. In case of an unknown subscriber continue with the normal
	 * delivery of the SMS.
	 */
	if (smpp_route_smpp_first()) {
		rc = smpp_try_deliver(gsms, msc_a);
		if (rc == GSM411_RP_CAUSE_MO_NUM_UNASSIGNED)
			/* unknown subscriber, try local */
			goto try_local;
		if (rc < 0) {
			LOG_TRANS(trans, LOGL_ERROR, "SMS delivery error: %d\n", rc);
	 		rc = GSM411_RP_CAUSE_MO_TEMP_FAIL;
			/* rc will be logged by gsm411_send_rp_error() */
			rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_SMS_DELIVER_UNKNOWN_ERROR]);
		}
		return rc;
	}

try_local:
#endif

	/* determine gsms->receiver based on dialled number */
	gsms->receiver = vlr_subscr_find_by_msisdn(net->vlr, gsms->dst.addr, VSUB_USE_SMS_RECEIVER);
	if (gsms->receiver)
		return 0;

#ifdef BUILD_SMPP
	/* Avoid a second look-up */
	if (smpp_route_smpp_first()) {
		rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_SMS_NO_RECEIVER]);
		return GSM411_RP_CAUSE_MO_NUM_UNASSIGNED;
	}

	rc = smpp_try_deliver(gsms, msc_a);
	if (rc == GSM411_RP_CAUSE_MO_NUM_UNASSIGNED) {
		rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_SMS_NO_RECEIVER]);
	} else if (rc < 0) {
		LOG_TRANS(trans, LOGL_ERROR, "SMS delivery error: %d\n", rc);
		rc = GSM411_RP_CAUSE_MO_TEMP_FAIL;
		/* rc will be logged by gsm411_send_rp_error() */
		rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_SMS_DELIVER_UNKNOWN_ERROR]);
	}
#else
	rc = GSM411_RP_CAUSE_MO_NUM_UNASSIGNED;
	rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_SMS_NO_RECEIVER]);
#endif

	return rc;
}


/* process an incoming TPDU (called from RP-DATA)
 * return value > 0: RP CAUSE for ERROR; < 0: silent error; 0 = success */
static int gsm340_rx_tpdu(struct gsm_trans *trans, struct msgb *msg,
			  uint32_t gsm411_msg_ref)
{
	uint8_t *smsp = msgb_sms(msg);
	struct gsm_sms *gsms;
	unsigned int sms_alphabet;
	uint8_t sms_mti, sms_vpf;
	uint8_t *sms_vp;
	uint8_t da_len_bytes;
	uint8_t address_lv[12]; /* according to 03.40 / 9.1.2.5 */
	int rc = 0;
	struct gsm_network *net;
	struct vlr_subscr *vsub;

	if (!trans->msc_a) {
		LOG_TRANS(trans, LOGL_ERROR, "Insufficient info to process TPDU: "
					     "MSC-A role is NULL?!?\n");
		return GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER;
	}

	net = msc_a_net(trans->msc_a);
	vsub = msc_a_vsub(trans->msc_a);
	if (!net || !vsub) {
		LOG_TRANS(trans, LOGL_ERROR, "Insufficient info to process TPDU: "
					     "gsm_network and/or vlr_subscr is NULL?!?\n");
		return GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER;
	}

	/* FIXME: should we do this on success, after all checks? */
	rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_SMS_SUBMITTED]);

	gsms = sms_alloc();
	if (!gsms)
		return GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER;

	/* invert those fields where 0 means active/present */
	sms_mti = *smsp & 0x03;
	sms_vpf = (*smsp & 0x18) >> 3;
	gsms->status_rep_req = (*smsp & 0x20) >> 5;
	gsms->ud_hdr_ind = (*smsp & 0x40);
	/*
	 * Not evaluating MMS (More Messages to Send) because the
	 * lchan stays open anyway.
	 * Not evaluating RP (Reply Path) because we're not aware of its
	 * benefits.
	 */

	smsp++;
	gsms->msg_ref = *smsp++;

	gsms->gsm411.transaction_id = trans->transaction_id;
	gsms->gsm411.msg_ref = gsm411_msg_ref;

	/* length in bytes of the destination address */
	da_len_bytes = 2 + *smsp/2 + *smsp%2;
	if (da_len_bytes > 12) {
		LOG_TRANS(trans, LOGL_ERROR, "Destination Address > 12 bytes ?!?\n");
		rc = GSM411_RP_CAUSE_SEMANT_INC_MSG;
		goto out;
	} else if (da_len_bytes < 4) {
		LOG_TRANS(trans, LOGL_ERROR, "Destination Address < 4 bytes ?!?\n");
		rc = GSM411_RP_CAUSE_SEMANT_INC_MSG;
		goto out;
	}
	memset(address_lv, 0, sizeof(address_lv));
	memcpy(address_lv, smsp, da_len_bytes);
	/* mangle first byte to reflect length in bytes, not digits */
	address_lv[0] = da_len_bytes - 1;

	gsms->dst.ton = (address_lv[1] >> 4) & 7;
	gsms->dst.npi = address_lv[1] & 0xF;
	/* convert to real number */
	if (gsm48_decode_bcd_number2(gsms->dst.addr,
				     sizeof(gsms->dst.addr), address_lv, da_len_bytes, 1)) {
		LOG_TRANS(trans, LOGL_ERROR, "Failed to decode destination Address\n");
		rc = GSM411_RP_CAUSE_SEMANT_INC_MSG;
		goto out;
	}
	smsp += da_len_bytes;

	gsms->protocol_id = *smsp++;
	gsms->data_coding_scheme = *smsp++;

	sms_alphabet = gsm338_get_sms_alphabet(gsms->data_coding_scheme);
	if (sms_alphabet == 0xffffffff) {
		rc = GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER;
		goto out;
	}

	switch (sms_vpf) {
	case GSM340_TP_VPF_RELATIVE:
		sms_vp = smsp++;
		break;
	case GSM340_TP_VPF_ABSOLUTE:
	case GSM340_TP_VPF_ENHANCED:
		sms_vp = smsp;
		/* the additional functionality indicator... */
		if (sms_vpf == GSM340_TP_VPF_ENHANCED && *smsp & (1<<7))
			smsp++;
		smsp += 7;
		break;
	case GSM340_TP_VPF_NONE:
		sms_vp = 0;
		break;
	default:
		LOG_TRANS(trans, LOGL_NOTICE, "SMS Validity period not implemented: 0x%02x\n", sms_vpf);
		rc = GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER;
		goto out;
	}

	/* As per 3GPP TS 03.40, section 9.2.3.16, TP-User-Data-Length (TP-UDL)
	 * may indicate either the number of septets, or the number of octets,
	 * depending on Data Coding Scheme. We store TP-UDL value as-is,
	 * so this should be kept in mind to avoid buffer overruns. */
	gsms->user_data_len = *smsp++;
	if (gsms->user_data_len > 0) {
		if (sms_alphabet == DCS_7BIT_DEFAULT) {
			/* TP-UDL is indicated in septets (up to 160) */
			if (gsms->user_data_len > GSM340_UDL_SPT_MAX) {
				LOG_TRANS(trans, LOGL_NOTICE,
					  "TP-User-Data-Length %u (septets) "
					  "is too big, truncating to %u\n",
					  gsms->user_data_len, GSM340_UDL_SPT_MAX);
				gsms->user_data_len = GSM340_UDL_SPT_MAX;
			}
			memcpy(gsms->user_data, smsp, gsm_get_octet_len(gsms->user_data_len));
			gsm_7bit_decode_n(gsms->text, sizeof(gsms->text),
					  smsp, gsms->user_data_len);
		} else {
			/* TP-UDL is indicated in octets (up to 140) */
			if (gsms->user_data_len > GSM340_UDL_OCT_MAX) {
				LOG_TRANS(trans, LOGL_NOTICE,
					  "TP-User-Data-Length %u (octets) "
					  "is too big, truncating to %u\n",
					  gsms->user_data_len, GSM340_UDL_OCT_MAX);
				gsms->user_data_len = GSM340_UDL_OCT_MAX;
			}
			memcpy(gsms->user_data, smsp, gsms->user_data_len);
		}
	}

	OSMO_STRLCPY_ARRAY(gsms->src.addr, vsub->msisdn);

	LOG_TRANS(trans, LOGL_INFO,
		  "MO SMS -- MTI: 0x%02x, VPF: 0x%02x, "
		  "MR: 0x%02x PID: 0x%02x, DCS: 0x%02x, DA: %s, "
		  "UserDataLength: 0x%02x, UserData: \"%s\"\n",
		  sms_mti, sms_vpf, gsms->msg_ref,
		  gsms->protocol_id, gsms->data_coding_scheme, gsms->dst.addr,
		  gsms->user_data_len,
		  sms_alphabet == DCS_7BIT_DEFAULT ? gsms->text :
		  osmo_hexdump(gsms->user_data, gsms->user_data_len));

	gsms->validity_minutes = gsm340_validity_period(sms_vpf, sms_vp);

	rc = sms_route_mt_sms(trans, gsms);

	/* This SMS got routed through SMPP and we are waiting on the response. */
	if (gsms->smpp.esme) {
		return -EINPROGRESS;
	}

	/* This SMS got routed through SMPP, but the configured ESME was
	 * unavailable at this time. This is an OOO condition.
	 * Don't store this SMS in the database as we may never be
	 * able to deliver it. (we would need to process the stored SMS and
	 * attempt re-submission to the ESME)
	 */
	if (rc == GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER)
		return rc;

	/*
	 * This SMS got routed through SMPP or no receiver exists.
	 * In any case, we store it in the database for further processing.
	 */

	switch (sms_mti) {
	case GSM340_SMS_SUBMIT_MS2SC:
		/* MS is submitting a SMS */
		rc = gsm340_rx_sms_submit(trans, gsms);
		break;
	case GSM340_SMS_COMMAND_MS2SC:
	case GSM340_SMS_DELIVER_REP_MS2SC:
		LOG_TRANS(trans, LOGL_NOTICE, "Unimplemented MTI 0x%02x\n", sms_mti);
		rc = GSM411_RP_CAUSE_IE_NOTEXIST;
		break;
	default:
		LOG_TRANS(trans, LOGL_NOTICE, "Undefined MTI 0x%02x\n", sms_mti);
		rc = GSM411_RP_CAUSE_IE_NOTEXIST;
		break;
	}
out:
	sms_free(gsms);

	return rc;
}

/* Prefix msg with a RP-DATA header and send as SMR DATA */
static int gsm411_rp_sendmsg(struct gsm411_smr_inst *inst, struct msgb *msg,
			     uint8_t rp_msg_type, uint8_t rp_msg_ref,
			     int rl_msg_type)
{
	struct gsm411_rp_hdr *rp;
	uint8_t len = msg->len;

	/* GSM 04.11 RP-DATA header */
	rp = (struct gsm411_rp_hdr *)msgb_push(msg, sizeof(*rp));
	rp->len = len + 2;
	rp->msg_type = rp_msg_type;
	rp->msg_ref = rp_msg_ref;

	return gsm411_smr_send(inst, rl_msg_type, msg);
}

int gsm411_send_rp_ack(struct gsm_trans *trans, uint8_t msg_ref)
{
	struct msgb *msg = gsm411_msgb_alloc();

	LOG_TRANS(trans, LOGL_DEBUG, "TX: SMS RP ACK\n");

	return gsm411_rp_sendmsg(&trans->sms.smr_inst, msg, GSM411_MT_RP_ACK_MT,
		msg_ref, GSM411_SM_RL_REPORT_REQ);
}

int gsm411_send_rp_error(struct gsm_trans *trans, uint8_t msg_ref,
			 uint8_t cause)
{
	struct msgb *msg = gsm411_msgb_alloc();

	msgb_tv_put(msg, 1, cause);

	LOG_TRANS(trans, LOGL_NOTICE, "TX: SMS RP ERROR, cause %d (%s)\n", cause,
		get_value_string(gsm411_rp_cause_strs, cause));

	return gsm411_rp_sendmsg(&trans->sms.smr_inst, msg,
		GSM411_MT_RP_ERROR_MT, msg_ref, GSM411_SM_RL_REPORT_REQ);
}

/* Receive a 04.11 TPDU inside RP-DATA / user data */
static int gsm411_rx_rp_ud(struct msgb *msg, struct gsm_trans *trans,
			  struct gsm411_rp_hdr *rph,
			  uint8_t *dst, uint8_t dst_len)
{
	int rc = 0;

	if (trans->net->sms_over_gsup) {
		/* RP-ACK or RP-ERROR is triggered as soon as we get the response */
		rc = gsm411_gsup_mo_fwd_sm_req(trans, msg, rph->msg_ref, dst, dst_len);
		if (rc) /* GSUP message sending error */
			return gsm411_send_rp_error(trans, rph->msg_ref, rc);

		return 0;
	}

	rc = gsm340_rx_tpdu(trans, msg, rph->msg_ref);
	if (rc == 0)
		return gsm411_send_rp_ack(trans, rph->msg_ref);
	else if (rc > 0)
		return gsm411_send_rp_error(trans, rph->msg_ref, rc);
	else if (rc == -EINPROGRESS)
		rc = 0;

	return rc;
}

/* Receive a 04.11 RP-DATA message in accordance with Section 7.3.1.2 */
static int gsm411_rx_rp_data(struct msgb *msg, struct gsm_trans *trans,
			     struct gsm411_rp_hdr *rph)
{
	uint8_t src_len, dst_len, rpud_len;
	uint8_t *src = NULL, *dst = NULL , *rp_ud = NULL;

	/* in the MO case, this should always be zero length */
	src_len = rph->data[0];
	if (src_len)
		src = &rph->data[1];

	dst_len = rph->data[1+src_len];
	if (dst_len)
		dst = &rph->data[1+src_len+1];

	rpud_len = rph->data[1+src_len+1+dst_len];
	if (rpud_len)
		rp_ud = &rph->data[1+src_len+1+dst_len+1];

	LOG_TRANS(trans, LOGL_DEBUG, "RX_RP-DATA: src_len=%u, dst_len=%u ud_len=%u\n",
		src_len, dst_len, rpud_len);

	if (src_len && src)
		LOG_TRANS(trans, LOGL_ERROR, "RP-DATA (MO) with SRC ?!?\n");

	if (!dst_len || !dst || !rpud_len || !rp_ud) {
		LOG_TRANS(trans, LOGL_ERROR,
			"RP-DATA (MO) without DST or TPDU ?!?\n");
		gsm411_send_rp_error(trans, rph->msg_ref,
				     GSM411_RP_CAUSE_INV_MAND_INF);
		return -EIO;
	}

	msg->l4h = rp_ud;

	LOG_TRANS(trans, LOGL_DEBUG, "DST(%u,%s)\n", dst_len, osmo_hexdump(dst, dst_len));

	return gsm411_rx_rp_ud(msg, trans, rph, dst, dst_len);
}

static struct gsm_sms *sms_report_alloc(struct gsm_sms *sms, struct gsm_trans *trans)
{
	struct gsm_sms *sms_report;
	int len;

	sms_report = sms_alloc();
	OSMO_ASSERT(sms_report);

	sms_report->msg_ref = sms->msg_ref;
	sms_report->protocol_id = sms->protocol_id;
	sms_report->data_coding_scheme = GSM338_DCS_1111_8BIT_DATA;

	/* Invert address to send status report back to origin. */
	sms_report->src = sms->dst;
	sms_report->dst = sms->src;

	/* As specified by Appendix B. Delivery Receipt Format.
	 * TODO: Many fields in this string are just set with dummy values,
	 * 	 revisit this.
	 */
	len = snprintf((char *)sms_report->user_data,
		       sizeof(sms_report->user_data),
		       "id:%.08llu sub:000 dlvrd:000 submit date:YYMMDDhhmm done date:YYMMDDhhmm stat:DELIVRD err:000 text:%.20s",
		       sms->id, sms->text);
	sms_report->user_data_len = len;
	LOG_TRANS(trans, LOGL_NOTICE, "%s\n", sms_report->user_data);

	/* This represents a sms report. */
	sms_report->is_report = true;

	return sms_report;
}

static void sms_status_report(struct gsm_sms *gsms, struct gsm_trans *trans)
{
	struct gsm_sms *sms_report;
	int rc;

	sms_report = sms_report_alloc(gsms, trans);

	rc = sms_route_mt_sms(trans, sms_report);
	if (rc < 0) {
		LOG_TRANS(trans, LOGL_ERROR, "Failed to send status report! err=%d\n", rc);
		return;
	}

	/* No route via SMPP, send the GSM 03.40 status-report now. */
	if (sms_report->receiver)
		gsm340_rx_sms_submit(trans, sms_report);

	LOG_TRANS(trans, LOGL_NOTICE, "Status report has been sent\n");

	sms_free(sms_report);
}

int sms_mark_delivered = 0;

/* Receive a 04.11 RP-ACK message (response to RP-DATA from us) */
static int gsm411_rx_rp_ack(struct gsm_trans *trans,
			    struct gsm411_rp_hdr *rph)
{
	struct gsm_sms *sms = trans->sms.sms;

	/* Acnkowledgement to MT RP_DATA, i.e. the MS confirms it
	 * successfully received a SMS.  We can now safely mark it as
	 * transmitted */

	if (trans->net->sms_over_gsup) {
		/* Forward towards SMSC via GSUP */
		return gsm411_gsup_mt_fwd_sm_res(trans, rph->msg_ref);
	}

	if (!sms) {
		LOG_TRANS(trans, LOGL_ERROR, "RX RP-ACK but no sms in transaction?!?\n");
		return gsm411_send_rp_error(trans, rph->msg_ref,
					    GSM411_RP_CAUSE_PROTOCOL_ERR);
	}

	/* mark this SMS as sent in database */
	if(sms_mark_delivered)
		db_sms_mark_delivered(sms);

	send_signal(S_SMS_DELIVERED, trans, sms, 0);

	if (sms->status_rep_req)
		sms_status_report(sms, trans);

	sms_free(sms);
	trans->sms.sms = NULL;

	return 0;
}

static int gsm411_rx_rp_error(struct gsm_trans *trans,
			      struct gsm411_rp_hdr *rph)
{
	struct msc_a *msc_a = trans->msc_a;
	struct gsm_network *net = msc_a_net(msc_a);
	struct gsm_sms *sms = trans->sms.sms;
	uint8_t cause_len = rph->data[0];
	uint8_t cause = rph->data[1];

	/* Error in response to MT RP_DATA, i.e. the MS did not
	 * successfully receive the SMS.  We need to investigate
	 * the cause and take action depending on it */

	LOG_TRANS(trans, LOGL_NOTICE, "RX SMS RP-ERROR, cause %d:%d (%s)\n",
		      cause_len, cause, get_value_string(gsm411_rp_cause_strs, cause));

	if (trans->net->sms_over_gsup) {
		/* Forward towards SMSC via GSUP */
		return gsm411_gsup_mt_fwd_sm_err(trans, rph->msg_ref, cause);
	}

	if (!sms) {
		LOG_TRANS(trans, LOGL_ERROR, "RX RP-ERR, but no sms in transaction?!?\n");
		return -EINVAL;
#if 0
		return gsm411_send_rp_error(trans, rph->msg_ref,
					    GSM411_RP_CAUSE_PROTOCOL_ERR);
#endif
	}

	if (cause == GSM411_RP_CAUSE_MT_MEM_EXCEEDED) {
		/* MS has not enough memory to store the message.  We need
		 * to store this in our database and wait for a SMMA message */
		/* FIXME */
		send_signal(S_SMS_MEM_EXCEEDED, trans, sms, 0);
		rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_SMS_RP_ERR_MEM]);
	} else {
		send_signal(S_SMS_UNKNOWN_ERROR, trans, sms, 0);
		rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_SMS_RP_ERR_OTHER]);
	}

	sms_free(sms);
	trans->sms.sms = NULL;

	return 0;
}

static int gsm411_rx_rp_smma(struct msgb *msg, struct gsm_trans *trans,
			     struct gsm411_rp_hdr *rph)
{
	int rc;

	if (trans->net->sms_over_gsup) {
		/* RP-ACK or RP-ERROR is triggered as soon as we get the response */
		rc = gsm411_gsup_mo_ready_for_sm_req(trans, rph->msg_ref);
		if (rc) /* GSUP message sending error */
			return gsm411_send_rp_error(trans, rph->msg_ref, rc);

		return 0;
	}

	rc = gsm411_send_rp_ack(trans, rph->msg_ref);

	/* MS tells us that it has memory for more SMS, we need
	 * to check if we have any pending messages for it and then
	 * transfer those */
	send_signal(S_SMS_SMMA, trans, NULL, 0);

	return rc;
}

/* receive RL DATA */
static int gsm411_rx_rl_data(struct msgb *msg, struct gsm48_hdr *gh,
			     struct gsm_trans *trans)
{
	struct gsm411_rp_hdr *rp_data = (struct gsm411_rp_hdr*)&gh->data;
	uint8_t msg_type =  rp_data->msg_type & 0x07;
	int rc = 0;

	switch (msg_type) {
	case GSM411_MT_RP_DATA_MO:
		LOG_TRANS(trans, LOGL_DEBUG, "RX SMS RP-DATA (MO)\n");
		rc = gsm411_rx_rp_data(msg, trans, rp_data);
		break;
	case GSM411_MT_RP_SMMA_MO:
		LOG_TRANS(trans, LOGL_DEBUG, "RX SMS RP-SMMA\n");
		rc = gsm411_rx_rp_smma(msg, trans, rp_data);
		break;
	default:
		LOG_TRANS(trans, LOGL_NOTICE, "Invalid RP type 0x%02x\n", msg_type);
		rc = -EINVAL;
		break;
	}

	return rc;
}

/* receive RL REPORT */
static int gsm411_rx_rl_report(struct msgb *msg, struct gsm48_hdr *gh,
			     struct gsm_trans *trans)
{
	struct gsm411_rp_hdr *rp_data = (struct gsm411_rp_hdr*)&gh->data;
	uint8_t msg_type =  rp_data->msg_type & 0x07;
	int rc = 0;

	switch (msg_type) {
	case GSM411_MT_RP_ACK_MO:
		LOG_TRANS(trans, LOGL_DEBUG, "RX SMS RP-ACK (MO)\n");
		rc = gsm411_rx_rp_ack(trans, rp_data);
		break;
	case GSM411_MT_RP_ERROR_MO:
		LOG_TRANS(trans, LOGL_DEBUG, "RX SMS RP-ERROR (MO)\n");
		rc = gsm411_rx_rp_error(trans, rp_data);
		break;
	default:
		LOG_TRANS(trans, LOGL_NOTICE, "Invalid RP type 0x%02x\n", msg_type);
		rc = -EINVAL;
		break;
	}

	return rc;
}

/* receive SM-RL sap message from SMR
 * NOTE: Message is freed by sender
 */
int gsm411_rl_recv(struct gsm411_smr_inst *inst, int msg_type,
                        struct msgb *msg)
{
	struct gsm_trans *trans =
		container_of(inst, struct gsm_trans, sms.smr_inst);
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (msg_type) {
	case GSM411_SM_RL_DATA_IND:
		rc = gsm411_rx_rl_data(msg, gh, trans);
		break;
	case GSM411_SM_RL_REPORT_IND:
		if (gh)
			rc = gsm411_rx_rl_report(msg, gh, trans);
		break;
	default:
		LOG_TRANS(trans, LOGL_NOTICE, "Unhandled SM-RL message 0x%x\n", msg_type);
		rc = -EINVAL;
	}

	return rc;
}

/* receive MNCCSMS sap message from SMC
 * NOTE: Message is freed by sender
 */
static int gsm411_mn_recv(struct gsm411_smc_inst *inst, int msg_type,
			struct msgb *msg)
{
	struct gsm_trans *trans =
		container_of(inst, struct gsm_trans, sms.smc_inst);
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (msg_type) {
	case GSM411_MNSMS_EST_IND:
	case GSM411_MNSMS_DATA_IND:
		LOG_TRANS(trans, LOGL_DEBUG, "MNSMS-DATA/EST-IND\n");
		rc = gsm411_smr_recv(&trans->sms.smr_inst, msg_type, msg);
		break;
	case GSM411_MNSMS_ERROR_IND:
		if (gh)
			LOG_TRANS(trans, LOGL_DEBUG, "MNSMS-ERROR-IND, cause %d (%s)\n",
				gh->data[0],
				get_value_string(gsm411_cp_cause_strs,
				gh->data[0]));
		else
			LOG_TRANS(trans, LOGL_DEBUG, "MNSMS-ERROR-IND, no cause\n");
		rc = gsm411_smr_recv(&trans->sms.smr_inst, msg_type, msg);
		break;
	default:
		LOG_TRANS(trans, LOGL_NOTICE, "Unhandled MNCCSMS msg 0x%x\n", msg_type);
		rc = -EINVAL;
	}

	return rc;
}

static struct gsm_trans *gsm411_trans_init(struct gsm_network *net, struct vlr_subscr *vsub, struct msc_a *msc_a,
					   uint8_t tid, bool mo)
{
	/* Allocate a new transaction */
	struct gsm_trans *trans = trans_alloc(net, vsub, TRANS_SMS, tid, new_callref++);
	if (!trans) {
		LOG_TRANS(trans, LOGL_ERROR, "No memory for transaction\n");
		return NULL;
	}

	if (msc_a) {
		msc_a_get(msc_a, MSC_A_USE_SMS);
		trans->msc_a = msc_a;

		osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_A_EV_TRANSACTION_ACCEPTED, trans);
		if (mo) {
			if (!osmo_use_count_by(&msc_a->use_count, MSC_A_USE_CM_SERVICE_SMS))
				LOG_TRANS(trans, LOGL_ERROR, "MO SMS without prior CM Service Request\n");
			else
				msc_a_put(msc_a, MSC_A_USE_CM_SERVICE_SMS);
		}
	}

	/* Init both SMC and SMR state machines */
	gsm411_smc_init(&trans->sms.smc_inst, 0, 1,
		gsm411_mn_recv, gsm411_mm_send);
	gsm411_smr_init(&trans->sms.smr_inst, 0, 1,
		gsm411_rl_recv, gsm411_mn_send);

	return trans;
}

/* Assigns an (unused) SM-RP-MR value to a given transaction */
static int gsm411_assign_sm_rp_mr(struct gsm_trans *trans)
{
	uint8_t mr;

	/* After allocation a given transaction has zero-initialized
	 * SM-RP-MR value, so trans_find_by_sm_rp_mr() may consider
	 * 0x00 as used. This is why we "poison" this transaction
	 * using the highest value. */
	trans->sms.sm_rp_mr = 0xff;

	/* According to 8.2.3, MR is in the range 0 through 255 */
	for (mr = 0x00; mr < 0xff; mr++) {
		if (trans_find_by_sm_rp_mr(trans->net, trans->vsub, mr))
			continue; /* this MR is busy, find another one */
		/* An unused value has been found, assign it */
		trans->sms.sm_rp_mr = mr;
		return 0;
	}

	/* All possible values are busy */
	return -EBUSY;
}

static struct gsm_trans *gsm411_alloc_mt_trans(struct gsm_network *net,
					       struct vlr_subscr *vsub)
{
	struct msc_a *msc_a;
	struct gsm_trans *trans;
	int tid;

	/* Generate a new transaction ID */
	tid = trans_assign_trans_id(net, vsub, TRANS_SMS);
	if (tid == -1) {
		LOGP(DLSMS, LOGL_ERROR, "No available transaction IDs\n");
		return NULL;
	}

	/* Attempt to find an existing connection */
	msc_a = msc_a_for_vsub(vsub, true);

	/* Allocate a new transaction */
	trans = gsm411_trans_init(net, vsub, msc_a, tid, false);
	if (!trans)
		return NULL;

	LOG_TRANS(trans, LOGL_INFO, "Going to send a MT SMS\n");

	/* Assign a unique SM-RP Message Reference */
	if (gsm411_assign_sm_rp_mr(trans) != 0) {
		LOG_TRANS(trans, LOGL_ERROR, "Failed to assign SM-RP-MR\n");
		trans_free(trans);
		return NULL;
	}

	/* Use SAPI 3 (see GSM 04.11, section 2.3) */
	trans->dlci = UM_SAPI_SMS;

	return trans;
}

/* High-level function to send an SMS to a given subscriber */
int gsm411_send_sms(struct gsm_network *net,
		    struct vlr_subscr *vsub,
		    struct gsm_sms *sms)
{
	uint8_t *data, *rp_ud_len;
	struct gsm_trans *trans;
	struct msgb *msg;
	int rc;

	/* Allocate a new transaction for MT SMS */
	trans = gsm411_alloc_mt_trans(net, vsub);
	if (!trans) {
		send_signal(S_SMS_UNKNOWN_ERROR, NULL, sms, 0);
		sms_free(sms);
		return -ENOMEM;
	}

	/* Allocate a message buffer for to be encoded SMS */
	msg = gsm411_msgb_alloc();
	if (!msg) {
		send_signal(S_SMS_UNKNOWN_ERROR, NULL, sms, 0);
		trans_free(trans);
		sms_free(sms);
		return -ENOMEM;
	}

	/* Hardcode SMSC Originating Address for now */
	data = (uint8_t *)msgb_put(msg, 8);
	data[0] = 0x07;	/* originator length == 7 */
	data[1] = 0x91; /* type of number: international, ISDN */
	data[2] = 0x44; /* 447785016005 */
	data[3] = 0x77;
	data[4] = 0x58;
	data[5] = 0x10;
	data[6] = 0x06;
	data[7] = 0x50;

	/* Hardcoded Destination Address */
	data = (uint8_t *)msgb_put(msg, 1);
	data[0] = 0;	/* destination length == 0 */

	/* obtain a pointer for the rp_ud_len, so we can fill it later */
	rp_ud_len = (uint8_t *)msgb_put(msg, 1);

	if (sms->is_report) {
		/* generate the 03.40 SMS-STATUS-REPORT TPDU */
		rc = gsm340_gen_sms_status_report_tpdu(trans, msg, sms);
	} else {
		/* generate the 03.40 SMS-DELIVER TPDU */
		rc = gsm340_gen_sms_deliver_tpdu(trans, msg, sms);
	}
	if (rc < 0) {
		send_signal(S_SMS_UNKNOWN_ERROR, trans, sms, 0);
		sms_free(sms);
		trans_free(trans);
		msgb_free(msg);
		return rc;
	}

	*rp_ud_len = rc;

	/* Store a pointer to abstract SMS representation */
	trans->sms.sms = sms;

	rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_SMS_DELIVERED]);
	db_sms_inc_deliver_attempts(trans->sms.sms);

	return gsm411_rp_sendmsg(&trans->sms.smr_inst, msg,
		GSM411_MT_RP_DATA_MT, trans->sms.sm_rp_mr,
		GSM411_SM_RL_DATA_REQ);
}

/* Low-level function to send raw RP-DATA to a given subscriber */
int gsm411_send_rp_data(struct gsm_network *net, struct vlr_subscr *vsub,
			size_t sm_rp_oa_len, const uint8_t *sm_rp_oa,
			size_t sm_rp_ud_len, const uint8_t *sm_rp_ud,
			bool sm_rp_mmts_ind)
{
	struct gsm_trans *trans;
	struct msgb *msg;

	/* Allocate a new transaction for MT SMS */
	trans = gsm411_alloc_mt_trans(net, vsub);
	if (!trans)
		return -ENOMEM;

	/* Multi-part SMS: handle MMTS (More Messages to Send) indication */
	trans->sms.sm_rp_mmts_ind = sm_rp_mmts_ind;
	if (trans->msc_a != NULL)
		gsm411_handle_mmts_ind(trans);

	/* Allocate a message buffer for to be encoded SMS */
	msg = gsm411_msgb_alloc();
	if (!msg) {
		trans_free(trans);
		return -ENOMEM;
	}

	/* Encode SM-RP-OA (SMSC address) */
	msgb_lv_put(msg, sm_rp_oa_len, sm_rp_oa);

	/* Encode SM-RP-DA (shall be empty, len=0) */
	msgb_v_put(msg, 0x00);

	/* Encode RP-UD itself (SM TPDU) */
	msgb_lv_put(msg, sm_rp_ud_len, sm_rp_ud);

	rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_SMS_DELIVERED]);

	return gsm411_rp_sendmsg(&trans->sms.smr_inst, msg,
		GSM411_MT_RP_DATA_MT, trans->sms.sm_rp_mr,
		GSM411_SM_RL_DATA_REQ);
}

/* Entry point for incoming GSM48_PDISC_SMS from abis_rsl.c */
int gsm0411_rcv_sms(struct msc_a *msc_a, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t msg_type = gh->msg_type;
	uint8_t transaction_id = gsm48_hdr_trans_id_flip_ti(gh);
	struct gsm411_rp_hdr *rph = (struct gsm411_rp_hdr *) gh->data;
	struct gsm_trans *trans;
	int new_trans = 0;
	int rc = 0;
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);
	struct gsm_network *net = msc_a_net(msc_a);

	trans = trans_find_by_id(msc_a, TRANS_SMS, transaction_id);

	/*
	 * A transaction we created but don't know about?
	 */
	if (!trans && (transaction_id & 0x8) == 0) {
		LOG_TRANS(trans, LOGL_ERROR, "trans_id=%x allocated by us but known "
			"to us anymore. We are ignoring it, maybe a CP-ERROR "
			"from a MS?\n",
			transaction_id);
		return -EINVAL;
	}

	if (!trans) {
		new_trans = 1;
		trans = gsm411_trans_init(net, vsub, msc_a, transaction_id, true);
		if (!trans) {
			/* FIXME: send some error message */
			return -ENOMEM;
		}

		trans->sms.sm_rp_mr = rph->msg_ref; /* SM-RP Message Reference */
		trans->dlci = OMSC_LINKID_CB(msg); /* DLCI as received from BSC */
	}

	LOG_TRANS(trans, LOGL_DEBUG, "receiving SMS message %s\n",
		  gsm48_pdisc_msgtype_name(gsm48_hdr_pdisc(gh), gsm48_hdr_msg_type(gh)));

	/* According to section 5.3.4, due to structure of message flow on
	 * SAPI 0 and 3 it is possible that the CP-ACK of a short message
	 * transfer might not be received. In this case the reception of
	 * CP-DATA may be interpreted as the reception of the awaited
	 * CP-ACK (implicit) and CP-DATA message. */
	if (trans->sms.smc_inst.cp_state == GSM411_CPS_IDLE
	    && msg_type == GSM411_MT_CP_DATA) {
		int i;
		struct gsm_trans *ptrans;

		/* Scan through all remote initiated transactions */
		for (i=8; i<15; i++) {
			if (i == transaction_id)
				continue;

			ptrans = trans_find_by_id(msc_a, TRANS_SMS, i);
			if (!ptrans)
				continue;

			LOG_TRANS(ptrans, LOGL_DEBUG, "Implicit CP-ACK for trans_id=%x\n", i);

			/* Finish it for good */
			trans_free(ptrans);
		}
	}

	gsm411_smc_recv(&trans->sms.smc_inst,
		(new_trans) ? GSM411_MMSMS_EST_IND : GSM411_MMSMS_DATA_IND,
		msg, msg_type);

	return rc;
}

void _gsm411_sms_trans_free(struct gsm_trans *trans)
{
	/* cleanup SMS instance */
	gsm411_smr_clear(&trans->sms.smr_inst);
	trans->sms.smr_inst.rl_recv = NULL;
	trans->sms.smr_inst.mn_send = NULL;

	gsm411_smc_clear(&trans->sms.smc_inst);
	trans->sms.smc_inst.mn_recv = NULL;
	trans->sms.smc_inst.mm_send = NULL;

	if (trans->sms.sms) {
		LOG_TRANS(trans, LOGL_ERROR, "Freeing transaction that still contains an SMS -- discarding\n");
		send_signal(S_SMS_UNKNOWN_ERROR, trans, trans->sms.sms, 0);
		sms_free(trans->sms.sms);
		trans->sms.sms = NULL;
	}
}

/* Process incoming SAPI N-REJECT from BSC */
void gsm411_sapi_n_reject(struct msc_a *msc_a)
{
	struct gsm_network *net;
	struct gsm_trans *trans, *tmp;

	net = msc_a_net(msc_a);

	llist_for_each_entry_safe(trans, tmp, &net->trans_list, entry) {
		struct gsm_sms *sms;

		if (trans->msc_a != msc_a)
			continue;
		if (trans->type != TRANS_SMS)
			continue;

		sms = trans->sms.sms;
		if (!sms) {
			LOG_TRANS(trans, LOGL_ERROR, "SAPI Reject but no SMS.\n");
			continue;
		}

		send_signal(S_SMS_UNKNOWN_ERROR, trans, sms, 0);
		sms_free(sms);
		trans->sms.sms = NULL;
		trans_free(trans);
	}
}

