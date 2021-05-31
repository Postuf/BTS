/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2008-2016 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
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
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "config.h"

#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_04_08.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/transaction.h>
#include <osmocom/msc/vlr.h>
#include <osmocom/msc/msc_a.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/crypt/auth.h>

#include <osmocom/msc/msub.h>
#include <osmocom/msc/msc_roles.h>

#include <assert.h>


void *tall_locop_ctx;
void *tall_authciphop_ctx;

static int gsm0408_loc_upd_acc(struct msc_a *msc_a, uint32_t send_tmsi);

/*! Send a simple GSM 04.08 message without any payload
 * \param      conn      Active RAN connection
 * \param[in]  pdisc     Protocol discriminator
 * \param[in]  msg_type  Message type
 * \return     result of \ref gsm48_conn_sendmsg
 */
int gsm48_tx_simple(struct msc_a *msc_a, uint8_t pdisc, uint8_t msg_type)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 TX SIMPLE");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = pdisc;
	gh->msg_type = msg_type;

	return msc_a_tx_dtap_to_i(msc_a, msg);
}

/* clear all transactions globally; used in case of MNCC socket disconnect */
void gsm0408_clear_all_trans(struct gsm_network *net, enum trans_type type)
{
	struct gsm_trans *trans, *temp;

	LOGP(DCC, LOGL_NOTICE, "Clearing all currently active transactions!!!\n");

	llist_for_each_entry_safe(trans, temp, &net->trans_list, entry) {
		if (trans->type == type) {
			trans->callref = 0;
			trans_free(trans);
		}
	}
}

/* Chapter 9.2.14 : Send LOCATION UPDATING REJECT */
static int gsm0408_loc_upd_rej(struct msc_a *msc_a, uint8_t cause)
{
	struct msgb *msg;

	msg = gsm48_create_loc_upd_rej(cause);
	if (!msg) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR, "Failed to create msg for LOCATION UPDATING REJECT.\n");
		return -1;
	}

	LOG_MSC_A_CAT(msc_a, DMM, LOGL_INFO, "LOCATION UPDATING REJECT\n");

	return msc_a_tx_dtap_to_i(msc_a, msg);
}

/* Chapter 9.2.13 : Send LOCATION UPDATE ACCEPT */
static int gsm0408_loc_upd_acc(struct msc_a *msc_a, uint32_t send_tmsi)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 LOC UPD ACC");
	struct gsm48_hdr *gh;
	struct gsm48_loc_area_id *lai;
	struct gsm_network *net = msc_a_net(msc_a);
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);
	struct osmo_location_area_id laid = {
		.plmn = net->plmn,
		.lac = vsub->cgi.lai.lac,
	};
	uint8_t *l;
	int rc;
	struct osmo_mobile_identity mi = {};

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_ACCEPT;

	lai = (struct gsm48_loc_area_id *) msgb_put(msg, sizeof(*lai));
	gsm48_generate_lai2(lai, &laid);

	if (send_tmsi == GSM_RESERVED_TMSI) {
		/* we did not allocate a TMSI to the MS, so we need to
		 * include the IMSI in order for the MS to delete any
		 * old TMSI that might still be allocated */
		mi.type = GSM_MI_TYPE_IMSI;
		OSMO_STRLCPY_ARRAY(mi.imsi, vsub->imsi);
		DEBUGP(DMM, "-> %s LOCATION UPDATE ACCEPT\n",
		       vlr_subscr_name(vsub));
	} else {
		/* Include the TMSI, which means that the MS will send a
		 * TMSI REALLOCATION COMPLETE, and we should wait for
		 * that until T3250 expiration */
		mi.type = GSM_MI_TYPE_TMSI;
		mi.tmsi = send_tmsi;
		DEBUGP(DMM, "-> %s LOCATION UPDATE ACCEPT (TMSI = 0x%08x)\n",
		       vlr_subscr_name(vsub),
		       send_tmsi);
	}
	l = msgb_tl_put(msg, GSM48_IE_MOBILE_ID);
	rc = osmo_mobile_identity_encode_msgb(msg, &mi, false);
	if (rc < 0) {
		msgb_free(msg);
		return -EINVAL;
	}
	*l = rc;

	/* TODO: Follow-on proceed */
	/* TODO: CTS permission */
	/* TODO: Equivalent PLMNs */
	/* TODO: Emergency Number List */
	/* TODO: Per-MS T3312 */


	return msc_a_tx_dtap_to_i(msc_a, msg);
}

/* Transmit Chapter 9.2.10 Identity Request */
static int mm_tx_identity_req(struct msc_a *msc_a, uint8_t id_type)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 ID REQ");
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_ID_REQ;
	gh->data[0] = id_type;

	return msc_a_tx_dtap_to_i(msc_a, msg);
}

/* Parse Chapter 9.2.11 Identity Response */
static int mm_rx_id_resp(struct msc_a *msc_a, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t *mi_data = gh->data+1;
	uint8_t mi_len = gh->data[0];
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);
	struct osmo_mobile_identity mi;
	int rc;

	if (!vsub) {
		LOGP(DMM, LOGL_ERROR,
		     "Rx MM Identity Response: invalid: no subscriber\n");
		return -EINVAL;
	}

	/* There muct be at least one octet with MI type */
	if (!mi_len) {
		LOGP(DMM, LOGL_NOTICE, "MM Identity Response contains "
				       "malformed Mobile Identity\n");
		return -EINVAL;
	}

	rc = osmo_mobile_identity_decode(&mi, mi_data, mi_len, false);
	if (rc) {
		LOGP(DMM, LOGL_ERROR, "Failure to decode Mobile Identity in MM Identity Response (rc=%d)\n", rc);
		return -EINVAL;
	}

	/* Make sure we got what we expected */
	if (mi.type != msc_a->mm_id_req_type) {
		LOGP(DMM, LOGL_NOTICE, "MM Identity Response contains unexpected "
				       "Mobile Identity type %s (extected %s)\n",
				       gsm48_mi_type_name(mi.type),
				       gsm48_mi_type_name(msc_a->mm_id_req_type));
		return -EINVAL;
	}

	DEBUGP(DMM, "IDENTITY RESPONSE: %s\n", osmo_mobile_identity_to_str_c(OTC_SELECT, &mi));

	osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_IDENTITY, gh->data);

	return vlr_subscr_rx_id_resp(vsub, &mi);
}

/* 9.2.5 CM service accept */
static int msc_gsm48_tx_mm_serv_ack(struct msc_a *msc_a)
{
	struct msgb *msg;
	struct gsm48_hdr *gh;

	msg = gsm48_msgb_alloc_name("GSM 04.08 SERV ACC");

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_ACC;

	return msc_a_tx_dtap_to_i(msc_a, msg);
}

/* 9.2.6 CM service reject */
static int msc_gsm48_tx_mm_serv_rej(struct msc_a *msc_a,
				    enum gsm48_reject_value value)
{
	struct msgb *msg;

	msg = gsm48_create_mm_serv_rej(value);
	if (!msg) {
		LOGP(DMM, LOGL_ERROR, "Failed to allocate CM Service Reject.\n");
		return -1;
	}

	LOG_MSC_A_CAT(msc_a, DMM, LOGL_DEBUG,  "-> CM SERVICE Reject cause: %d\n", value);

	return msc_a_tx_dtap_to_i(msc_a, msg);
}


/* Extract the R99 flag from various Complete Level 3 messages. Depending on the Message Type, extract R99 from the
 * Classmark Type 1 or the Classmark Type 2. Return 1 for R99, 0 for pre-R99, negative if not a valid Complete Level 3
 * message. */
int compl_l3_msg_is_r99(const struct msgb *msg)
{
	const struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	const struct gsm48_loc_upd_req *lu;
	const struct gsm48_imsi_detach_ind *idi;
	uint8_t cm2_len;
	const struct gsm48_classmark2 *cm2;

	switch (pdisc) {
	case GSM48_PDISC_MM:
		switch (gsm48_hdr_msg_type(gh)) {
		case GSM48_MT_MM_LOC_UPD_REQUEST:
			lu = (const struct gsm48_loc_upd_req *) gh->data;
			return osmo_gsm48_classmark1_is_r99(&lu->classmark1) ? 1 : 0;

		case GSM48_MT_MM_CM_SERV_REQ:
		case GSM48_MT_MM_CM_REEST_REQ:
			break;

		case GSM48_MT_MM_IMSI_DETACH_IND:
			idi = (const struct gsm48_imsi_detach_ind *) gh->data;
			return osmo_gsm48_classmark1_is_r99(&idi->classmark1) ? 1 : 0;

		default:
			return -1;
		}
		break;

	case GSM48_PDISC_RR:
		switch (gsm48_hdr_msg_type(gh)) {
		case GSM48_MT_RR_PAG_RESP:
			break;

		default:
			return -1;
		}
		break;

	default:
		return -1;
	}

	/* Both CM Service Request and Paging Response have Classmark Type 2 at the same location: */
	cm2_len = gh->data[1];
	cm2 = (void*)gh->data+2;
	return osmo_gsm48_classmark2_is_r99(cm2, cm2_len) ? 1 : 0;
}

/* Chapter 9.2.15: Receive Location Updating Request.
 * Keep this function non-static for direct invocation by unit tests. */
static int mm_rx_loc_upd_req(struct msc_a *msc_a, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_loc_upd_req *lu;
	enum vlr_lu_type vlr_lu_type = VLR_LU_TYPE_REGULAR;
	uint32_t tmsi;
	char *imsi;
	struct osmo_location_area_id old_lai;
	struct osmo_fsm_inst *lu_fsm;
	bool is_utran;
	struct gsm_network *net = msc_a_net(msc_a);
	struct vlr_subscr *vsub;
	struct osmo_mobile_identity mi;
	int rc;

	rc = osmo_mobile_identity_decode_from_l3(&mi, msg, false);
	if (rc) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR,
			      "Failed to decode Mobile Identity in Location Updating Request\n");
		return -EINVAL;
	}

 	lu = (struct gsm48_loc_upd_req *) gh->data;

	if (msc_a_is_establishing_auth_ciph(msc_a)) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR,
			     "Cannot accept another LU, conn already busy establishing authenticity;"
			     " extraneous LOCATION UPDATING REQUEST: MI=%s LU-type=%s\n",
			     osmo_mobile_identity_to_str_c(OTC_SELECT, &mi), osmo_lu_type_name(lu->type));
		return -EINVAL;
	}

	if (msc_a_is_accepted(msc_a)) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR,
			     "Cannot accept another LU, conn already established;"
			     " extraneous LOCATION UPDATING REQUEST: MI=%s LU-type=%s\n",
			     osmo_mobile_identity_to_str_c(OTC_SELECT, &mi), osmo_lu_type_name(lu->type));
		return -EINVAL;
	}

	msc_a->complete_layer3_type = COMPLETE_LAYER3_LU;

	msub_update_id_from_mi(msc_a->c.msub, &mi);

	LOG_MSC_A_CAT(msc_a, DMM, LOGL_DEBUG, "LOCATION UPDATING REQUEST: MI=%s LU-type=%s\n",
		     osmo_mobile_identity_to_str_c(OTC_SELECT, &mi), osmo_lu_type_name(lu->type));

	osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_IDENTITY, &mi);

	switch (lu->type) {
	case GSM48_LUPD_NORMAL:
		rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_NORMAL]);
		vlr_lu_type = VLR_LU_TYPE_REGULAR;
		break;
	case GSM48_LUPD_IMSI_ATT:
		rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_ATTACH]);
		vlr_lu_type = VLR_LU_TYPE_IMSI_ATTACH;
		break;
	case GSM48_LUPD_PERIODIC:
		rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_PERIODIC]);
		vlr_lu_type = VLR_LU_TYPE_PERIODIC;
		break;
	}

	/* TODO: 10.5.1.6 MS Classmark for UMTS / Classmark 2 */
	/* TODO: 10.5.3.14 Additional update parameters (CS fallback calls) */
	/* TODO: 10.5.7.8 Device properties */
	/* TODO: 10.5.1.15 MS network feature support */

	switch (mi.type) {
	case GSM_MI_TYPE_IMSI:
		tmsi = GSM_RESERVED_TMSI;
		imsi = mi.imsi;
		break;
	case GSM_MI_TYPE_TMSI:
		tmsi = mi.tmsi;
		imsi = NULL;
		break;
	default:
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR, "unknown mobile identity type\n");
		tmsi = GSM_RESERVED_TMSI;
		imsi = NULL;
		break;
	}

	gsm48_decode_lai2(&lu->lai, &old_lai);
	LOG_MSC_A_CAT(msc_a, DMM, LOGL_DEBUG, "USIM: old LAI: %s\n", osmo_lai_name(&old_lai));

	msc_a_get(msc_a, __func__);
	msc_a_get(msc_a, MSC_A_USE_LOCATION_UPDATING);

	is_utran = (msc_a->c.ran->type == OSMO_RAT_UTRAN_IU);
	lu_fsm = vlr_loc_update(msc_a->c.fi,
				MSC_A_EV_AUTHENTICATED, MSC_A_EV_CN_CLOSE, NULL,
				net->vlr, msc_a, vlr_lu_type, tmsi, imsi,
				&old_lai, &msc_a->via_cell.lai,
				is_utran || net->authentication_required,
				is_utran ? net->uea_encryption : net->a5_encryption_mask > 0x01,
				lu->key_seq,
				osmo_gsm48_classmark1_is_r99(&lu->classmark1),
				is_utran,
				net->vlr->cfg.assign_tmsi);

	if (!lu_fsm) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Can't start LU FSM\n");
		msc_a_put(msc_a, MSC_A_USE_LOCATION_UPDATING);
		msc_a_put(msc_a, __func__);
		return 0;
	}

	/* From vlr_loc_update() we expect an implicit dispatch of
	 * VLR_ULA_E_UPDATE_LA, and thus we expect msc_vlr_subscr_assoc() to
	 * already have been called and completed. Has an error occurred? */

	vsub = msc_a_vsub(msc_a);
	if (!vsub) {
		msc_a_put(msc_a, __func__);
		return 0;
	}

	if (vsub->lu_fsm != lu_fsm) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Internal Error during Location Updating attempt\n");
		msc_a_release_cn(msc_a);
		msc_a_put(msc_a, __func__);
		return -EIO;
	}

	vsub->classmark.classmark1 = lu->classmark1;
	vsub->classmark.classmark1_set = true;
	msc_a_put(msc_a, __func__);
	return 0;
}

/* Turn int into semi-octet representation: 98 => 0x89 */
/* FIXME: libosmocore/libosmogsm */
static uint8_t bcdify(uint8_t value)
{
        uint8_t ret;

        ret = value / 10;
        ret |= (value % 10) << 4;

        return ret;
}

/* Generate a message buffer that contains a valid MM info message,
 * See also 3GPP TS 24.008, chapter 9.2.15a */
struct msgb *gsm48_create_mm_info(struct gsm_network *net)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 MM INF");
	struct gsm48_hdr *gh;
	uint8_t *ptr8;
	int name_len, name_pad;

	time_t cur_t;
	struct tm* gmt_time;
	struct tm* local_time;
	int tzunits;
	int dst = 0;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_INFO;

	if (net->name_long) {
#if 0
		name_len = strlen(net->name_long);
		/* 10.5.3.5a */
		ptr8 = msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_LONG;
		ptr8[1] = name_len*2 +1;
		ptr8[2] = 0x90; /* UCS2, no spare bits, no CI */

		ptr16 = (uint16_t *) msgb_put(msg, name_len*2);
		for (i = 0; i < name_len; i++)
			ptr16[i] = htons(net->name_long[i]);

		/* FIXME: Use Cell Broadcast, not UCS-2, since
		 * UCS-2 is only supported by later revisions of the spec */
#endif
		name_len = (strlen(net->name_long)*7)/8;
		name_pad = (8 - strlen(net->name_long)*7)%8;
		if (name_pad > 0)
			name_len++;
		/* 10.5.3.5a */
		ptr8 = msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_LONG;
		ptr8[1] = name_len +1;
		ptr8[2] = 0x80 | name_pad; /* Cell Broadcast DCS, no CI */

		ptr8 = msgb_put(msg, name_len);
		gsm_7bit_encode_n(ptr8, name_len, net->name_long, NULL);

	}

	if (net->name_short) {
#if 0
		name_len = strlen(net->name_short);
		/* 10.5.3.5a */
		ptr8 = (uint8_t *) msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_SHORT;
		ptr8[1] = name_len*2 + 1;
		ptr8[2] = 0x90; /* UCS2, no spare bits, no CI */

		ptr16 = (uint16_t *) msgb_put(msg, name_len*2);
		for (i = 0; i < name_len; i++)
			ptr16[i] = htons(net->name_short[i]);
#endif
		name_len = (strlen(net->name_short)*7)/8;
		name_pad = (8 - strlen(net->name_short)*7)%8;
		if (name_pad > 0)
			name_len++;
		/* 10.5.3.5a */
		ptr8 = (uint8_t *) msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_SHORT;
		ptr8[1] = name_len +1;
		ptr8[2] = 0x80 | name_pad; /* Cell Broadcast DCS, no CI */

		ptr8 = msgb_put(msg, name_len);
		gsm_7bit_encode_n(ptr8, name_len, net->name_short, NULL);

	}

	/* Section 10.5.3.9 */
	cur_t = time(NULL);
	gmt_time = gmtime(&cur_t);

	ptr8 = msgb_put(msg, 8);
	ptr8[0] = GSM48_IE_NET_TIME_TZ;
	ptr8[1] = bcdify(gmt_time->tm_year % 100);
	ptr8[2] = bcdify(gmt_time->tm_mon + 1);
	ptr8[3] = bcdify(gmt_time->tm_mday);
	ptr8[4] = bcdify(gmt_time->tm_hour);
	ptr8[5] = bcdify(gmt_time->tm_min);
	ptr8[6] = bcdify(gmt_time->tm_sec);

	if (net->tz.override) {
		/* Convert tz.hr and tz.mn to units */
		if (net->tz.hr < 0) {
			tzunits = ((net->tz.hr/-1)*4);
			tzunits = tzunits + (net->tz.mn/15);
			ptr8[7] = bcdify(tzunits);
			/* Set negative time */
			ptr8[7] |= 0x08;
		}
		else {
			tzunits = net->tz.hr*4;
			tzunits = tzunits + (net->tz.mn/15);
			ptr8[7] = bcdify(tzunits);
		}
		/* Convert DST value */
		if (net->tz.dst >= 0 && net->tz.dst <= 2)
			dst = net->tz.dst;
	}
	else {
		/* Need to get GSM offset and convert into 15 min units */
		/* This probably breaks if gmtoff returns a value not evenly divisible by 15? */
#ifdef HAVE_TM_GMTOFF_IN_TM
		local_time = localtime(&cur_t);
		tzunits = (local_time->tm_gmtoff/60)/15;
#else
		/* find timezone offset */
		time_t utc;
		double offsetFromUTC;
		utc = mktime(gmt_time);
		local_time = localtime(&cur_t);
		offsetFromUTC = difftime(cur_t, utc);
		if (local_time->tm_isdst)
			offsetFromUTC += 3600.0;
		tzunits = ((int)offsetFromUTC) / 60 / 15;
#endif
		if (tzunits < 0) {
			tzunits = tzunits/-1;
			ptr8[7] = bcdify(tzunits);
			/* Flip it to negative */
			ptr8[7] |= 0x08;
		}
		else
			ptr8[7] = bcdify(tzunits);

		/* Does not support DST +2 */
		if (local_time->tm_isdst)
			dst = 1;
	}

	if (dst) {
		ptr8 = msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NET_DST;
		ptr8[1] = 1;
		ptr8[2] = dst;
	}

	return msg;
}

/* Section 9.2.15a */
int gsm48_tx_mm_info(struct msc_a *msc_a)
{
	struct gsm_network *net = msc_a_net(msc_a);
	struct msgb *msg;

        msg = gsm48_create_mm_info(net);

	LOG_MSC_A(msc_a, LOGL_DEBUG, "Tx MM INFO\n");
	return msc_a_tx_dtap_to_i(msc_a, msg);
}

/*! Send an Authentication Request to MS on the given RAN connection
 * according to 3GPP/ETSI TS 24.008, Section 9.2.2.
 * \param[in] conn  Subscriber connection to send on.
 * \param[in] rand  Random challenge token to send, must be 16 bytes long.
 * \param[in] autn  r99: In case of UMTS mutual authentication, AUTN token to
 * 	send; must be 16 bytes long, or pass NULL for plain GSM auth.
 * \param[in] key_seq  auth tuple's sequence number.
 */
int gsm48_tx_mm_auth_req(struct msc_a *msc_a, uint8_t *rand,
			 uint8_t *autn, int key_seq)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 AUTH REQ");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_auth_req *ar = (struct gsm48_auth_req *) msgb_put(msg, sizeof(*ar));

	DEBUGP(DMM, "Tx AUTH REQ (rand = %s)\n", osmo_hexdump_nospc(rand, 16));
	if (autn)
		DEBUGP(DMM, "   AUTH REQ (autn = %s)\n", osmo_hexdump_nospc(autn, 16));

	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_AUTH_REQ;

	ar->key_seq = key_seq;

	/* 16 bytes RAND parameters */
	osmo_static_assert(sizeof(ar->rand) == 16, sizeof_auth_req_r99_rand);
	if (rand)
		memcpy(ar->rand, rand, 16);


	/* 16 bytes AUTN */
	if (autn)
		msgb_tlv_put(msg, GSM48_IE_AUTN, 16, autn);

	return msc_a_tx_dtap_to_i(msc_a, msg);
}

/* Section 9.2.1 */
int gsm48_tx_mm_auth_rej(struct msc_a *msc_a)
{
	LOG_MSC_A_CAT(msc_a, DMM, LOGL_DEBUG, "-> AUTH REJECT\n");
	return gsm48_tx_simple(msc_a, GSM48_PDISC_MM, GSM48_MT_MM_AUTH_REJ);
}

static int msc_vlr_tx_cm_serv_rej(void *msc_conn_ref, enum osmo_cm_service_type cm_service_type,
				  enum gsm48_reject_value cause);

static int cm_serv_reuse_conn(struct msc_a *msc_a, const struct osmo_mobile_identity *mi, enum osmo_cm_service_type cm_serv_type)
{
	struct gsm_network *net = msc_a_net(msc_a);
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);

	switch (mi->type) {
	case GSM_MI_TYPE_IMSI:
		if (vlr_subscr_matches_imsi(vsub, mi->imsi))
			goto accept_reuse;
		break;
	case GSM_MI_TYPE_TMSI:
		if (vlr_subscr_matches_tmsi(vsub, mi->tmsi))
			goto accept_reuse;
		break;
	case GSM_MI_TYPE_IMEI:
		if (vlr_subscr_matches_imei(vsub, mi->imei))
			goto accept_reuse;
		break;
	default:
		break;
	}

	LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR, "CM Service Request with mismatching mobile identity: %s\n",
		      osmo_mobile_identity_to_str_c(OTC_SELECT, mi));
	msc_vlr_tx_cm_serv_rej(msc_a, cm_serv_type, GSM48_REJECT_ILLEGAL_MS);
	return -EINVAL;

accept_reuse:
	LOG_MSC_A_CAT(msc_a, DMM, LOGL_DEBUG, "re-using already accepted connection\n");

	msc_a_get(msc_a, msc_a_cm_service_type_to_use(cm_serv_type));
	msub_update_id(msc_a->c.msub);
	return net->vlr->ops.tx_cm_serv_acc(msc_a, cm_serv_type);
}

/*
 * Handle CM Service Requests
 * a) Verify that the packet is long enough to contain the information
 *    we require otherwise reject with INCORRECT_MESSAGE
 * b) Try to parse the TMSI. If we do not have one reject
 * c) Check that we know the subscriber with the TMSI otherwise reject
 *    with a HLR cause
 * d) Set the subscriber on the conn and accept
 *
 * Keep this function non-static for direct invocation by unit tests.
 */
int gsm48_rx_mm_serv_req(struct msc_a *msc_a, struct msgb *msg)
{
	struct gsm_network *net = msc_a_net(msc_a);
	struct gsm48_hdr *gh;
	struct gsm48_service_request *req;
	struct gsm48_classmark2 *cm2;
	uint8_t *cm2_buf, cm2_len;
	bool is_utran;
	struct vlr_subscr *vsub;
	struct osmo_mobile_identity mi;
	int rc;

	/* Make sure that both header and CM Service Request fit into the buffer */
	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*req)) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Rx CM SERVICE REQUEST: wrong message size (%u < %zu)\n",
			  msgb_l3len(msg), sizeof(*gh) + sizeof(*req));
		return msc_gsm48_tx_mm_serv_rej(msc_a, GSM48_REJECT_INCORRECT_MESSAGE);
	}

	rc = osmo_mobile_identity_decode_from_l3(&mi, msg, false);
	if (rc) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Rx CM SERVICE REQUEST: unable to decode Mobile Identity\n");
		return msc_gsm48_tx_mm_serv_rej(msc_a, GSM48_REJECT_INCORRECT_MESSAGE);
	}

	gh = (struct gsm48_hdr *) msgb_l3(msg);
	req = (struct gsm48_service_request *) gh->data;

	/* Unfortunately in Phase1 the Classmark2 length is variable, so we cannot
	 * just use gsm48_service_request struct, and need to parse it manually. */
	cm2_len = gh->data[1];
	cm2_buf = gh->data + 2;
	cm2 = (struct gsm48_classmark2 *) cm2_buf;

	/* Prevent buffer overrun: check the length of Classmark2 */
	if (cm2_buf + cm2_len > msg->tail) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "Rx CM SERVICE REQUEST: Classmark2 "
					     "length=%u is too big\n", cm2_len);
		return msc_gsm48_tx_mm_serv_rej(msc_a, GSM48_REJECT_INCORRECT_MESSAGE);
	}

	if (msc_a_is_establishing_auth_ciph(msc_a)) {
		LOG_MSC_A(msc_a, LOGL_ERROR,
			  "Cannot accept CM Service Request, conn already busy establishing authenticity\n");
		return msc_gsm48_tx_mm_serv_rej(msc_a, GSM48_REJECT_CONGESTION);
		/* or should we accept and note down the service request anyway? */
	}

	msc_a->complete_layer3_type = COMPLETE_LAYER3_CM_SERVICE_REQ;
	msub_update_id_from_mi(msc_a->c.msub, &mi);
	LOG_MSC_A_CAT(msc_a, DMM, LOGL_DEBUG, "Rx CM SERVICE REQUEST cm_service_type=%s\n",
		     osmo_cm_service_type_name(req->cm_service_type));

	switch (mi.type) {
	case GSM_MI_TYPE_IMSI:
	case GSM_MI_TYPE_TMSI:
		/* continue below */
		break;
	case GSM_MI_TYPE_IMEI:
		if (req->cm_service_type == GSM48_CMSERV_EMERGENCY) {
			/* We don't do emergency calls by IMEI */
			LOG_MSC_A(msc_a, LOGL_NOTICE, "Tx CM SERVICE REQUEST REJECT: "
				  "emergency services by IMEI are not supported\n");
			return msc_gsm48_tx_mm_serv_rej(msc_a, GSM48_REJECT_IMEI_NOT_ACCEPTED);
		}
		/* fall-through for non-emergency setup */
	default:
		LOG_MSC_A(msc_a, LOGL_ERROR, "MI type is not expected: %s\n", gsm48_mi_type_name(mi.type));
		return msc_gsm48_tx_mm_serv_rej(msc_a, GSM48_REJECT_INCORRECT_MESSAGE);
	}

	if (!msc_a_cm_service_type_to_use(req->cm_service_type))
		return msc_gsm48_tx_mm_serv_rej(msc_a, GSM48_REJECT_SRV_OPT_NOT_SUPPORTED);

	if (msc_a_is_accepted(msc_a))
		return cm_serv_reuse_conn(msc_a, &mi, req->cm_service_type);

	osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_IDENTITY, &mi);

	msc_a_get(msc_a, msc_a_cm_service_type_to_use(req->cm_service_type));

	is_utran = (msc_a->c.ran->type == OSMO_RAT_UTRAN_IU);
	vlr_proc_acc_req(msc_a->c.fi,
			 MSC_A_EV_AUTHENTICATED, MSC_A_EV_CN_CLOSE, NULL,
			 net->vlr, msc_a,
			 VLR_PR_ARQ_T_CM_SERV_REQ,
			 req->cm_service_type,
			 &mi, &msc_a->via_cell.lai,
			 is_utran || net->authentication_required,
			 is_utran ? net->uea_encryption : net->a5_encryption_mask > 0x01,
			 req->cipher_key_seq,
			 osmo_gsm48_classmark2_is_r99(cm2, cm2_len),
			 is_utran);

	/* From vlr_proc_acc_req() we expect an implicit dispatch of PR_ARQ_E_START we expect
	 * msc_vlr_subscr_assoc() to already have been called and completed. Has an error occurred? */
	vsub = msc_a_vsub(msc_a);
	if (!vsub) {
		LOG_MSC_A(msc_a, LOGL_ERROR, "subscriber not allowed to do a CM Service Request\n");
		return -EIO;
	}

	vsub->classmark.classmark2 = *cm2;
	vsub->classmark.classmark2_len = cm2_len;
	return 0;
}

/* Receive a CM Re-establish Request */
static int gsm48_rx_cm_reest_req(struct msc_a *msc_a, struct msgb *msg)
{
	struct osmo_mobile_identity mi;
	int rc = osmo_mobile_identity_decode_from_l3(&mi, msg, false);
	if (rc) {
		LOGP(DMM, LOGL_ERROR, "CM RE-ESTABLISH REQUEST: cannot decode Mobile Identity\n");
		return -EINVAL;
	}

	DEBUGP(DMM, "<- CM RE-ESTABLISH REQUEST %s\n", osmo_mobile_identity_to_str_c(OTC_SELECT, &mi));

	/* we don't support CM call re-establishment */
	return msc_gsm48_tx_mm_serv_rej(msc_a, GSM48_REJECT_SRV_OPT_NOT_SUPPORTED);
}

static int gsm48_rx_mm_imsi_detach_ind(struct msc_a *msc_a, struct msgb *msg)
{
	struct gsm_network *net = msc_a_net(msc_a);
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_imsi_detach_ind *idi =
				(struct gsm48_imsi_detach_ind *) gh->data;
	struct osmo_mobile_identity mi;
	struct vlr_subscr *vsub = NULL;

	int rc = osmo_mobile_identity_decode_from_l3(&mi, msg, false);
	if (rc) {
		LOGP(DMM, LOGL_ERROR, "IMSI DETACH INDICATION: cannot decode Mobile Identity\n");
		return -EINVAL;
	}

	DEBUGP(DMM, "IMSI DETACH INDICATION: %s\n", osmo_mobile_identity_to_str_c(OTC_SELECT, &mi));

	rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_DETACH]);

	switch (mi.type) {
	case GSM_MI_TYPE_TMSI:
		vsub = vlr_subscr_find_by_tmsi(net->vlr, mi.tmsi, __func__);
		break;
	case GSM_MI_TYPE_IMSI:
		vsub = vlr_subscr_find_by_imsi(net->vlr, mi.imsi, __func__);
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		/* no sim card... FIXME: what to do ? */
		LOGP(DMM, LOGL_ERROR, "%s: unimplemented mobile identity type\n",
		     osmo_mobile_identity_to_str_c(OTC_SELECT, &mi));
		break;
	default:
		LOGP(DMM, LOGL_ERROR, "%s: unknown mobile identity type\n",
		     osmo_mobile_identity_to_str_c(OTC_SELECT, &mi));
		break;
	}

	if (!vsub) {
		LOGP(DMM, LOGL_ERROR, "IMSI DETACH for unknown subscriber %s\n",
		     osmo_mobile_identity_to_str_c(OTC_SELECT, &mi));
	} else {
		LOGP(DMM, LOGL_INFO, "IMSI DETACH for %s\n", vlr_subscr_name(vsub));
		msub_set_vsub(msc_a->c.msub, vsub);

		if (vsub->cs.is_paging)
			paging_expired(vsub);

		vsub->classmark.classmark1 = idi->classmark1;

		vlr_subscr_rx_imsi_detach(vsub);
		osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_DETACHED, vsub);
		vlr_subscr_put(vsub, __func__);
	}

	msc_a_release_cn(msc_a);
	return 0;
}

static int gsm48_rx_mm_status(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DMM, "MM STATUS (reject cause 0x%02x)\n", gh->data[0]);

	return 0;
}

static int parse_gsm_auth_resp(uint8_t *res, uint8_t *res_len,
			       struct msc_a *msc_a,
			       struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_auth_resp *ar = (struct gsm48_auth_resp*) gh->data;

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*ar)) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR, "MM AUTHENTICATION RESPONSE: l3 length invalid: %u\n",
			      msgb_l3len(msg));
		return -EINVAL;
	}

	*res_len = sizeof(ar->sres);
	memcpy(res, ar->sres, sizeof(ar->sres));
	return 0;
}

static int parse_umts_auth_resp(uint8_t *res, uint8_t *res_len,
				struct msc_a *msc_a,
				struct msgb *msg)
{
	struct gsm48_hdr *gh;
	uint8_t *data;
	uint8_t iei;
	uint8_t ie_len;
	unsigned int data_len;

	/* First parse the GSM part */
	if (parse_gsm_auth_resp(res, res_len, msc_a, msg))
		return -EINVAL;
	OSMO_ASSERT(*res_len == 4);

	/* Then add the extended res part */
	gh = msgb_l3(msg);
	data = gh->data + sizeof(struct gsm48_auth_resp);
	data_len = msgb_l3len(msg) - (data - (uint8_t*)msgb_l3(msg));

	if (data_len < 3) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR, "MM AUTHENTICATION RESPONSE: "
			      "message length=%u is too short\n", data_len);
		return -EINVAL;
	}

	iei = data[0];
	ie_len = data[1];
	if (iei != GSM48_IE_AUTH_RES_EXT) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR, "MM R99 AUTHENTICATION RESPONSE: expected IEI 0x%02x, got 0x%02x\n",
			      GSM48_IE_AUTH_RES_EXT, iei);
		return -EINVAL;
	}

	if (ie_len > 12) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR,
			      "MM R99 AUTHENTICATION RESPONSE: extended Auth Resp IE 0x%02x is too large: %u bytes\n",
			      GSM48_IE_AUTH_RES_EXT, ie_len);
		return -EINVAL;
	}

	*res_len += ie_len;
	memcpy(res + 4, &data[2], ie_len);
	return 0;
}

/* Chapter 9.2.3: Authentication Response */
static int gsm48_rx_mm_auth_resp(struct msc_a *msc_a, struct msgb *msg)
{
	uint8_t res[16];
	uint8_t res_len;
	int rc;
	bool is_umts;
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);

	if (!vsub) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR, "MM AUTHENTICATION RESPONSE: invalid: no subscriber\n");
		msc_a_release_mo(msc_a, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	is_umts = (msgb_l3len(msg) > sizeof(struct gsm48_hdr) + sizeof(struct gsm48_auth_resp));

	if (is_umts)
		rc = parse_umts_auth_resp(res, &res_len, msc_a, msg);
	else
		rc = parse_gsm_auth_resp(res, &res_len, msc_a, msg);

	if (rc) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR,
			      "MM AUTHENTICATION RESPONSE: invalid: parsing %s AKA Auth Response"
			      " failed with rc=%d; dispatching zero length SRES/RES to trigger failure\n",
			      is_umts ? "UMTS" : "GSM", rc);
		memset(res, 0, sizeof(res));
		res_len = 0;
	}

	LOG_MSC_A_CAT(msc_a, DMM, LOGL_DEBUG, "MM %s AUTHENTICATION RESPONSE (%s = %s)\n",
		      is_umts ? "UMTS" : "GSM", is_umts ? "res" : "sres",
		      osmo_hexdump_nospc(res, res_len));

	return vlr_subscr_rx_auth_resp(vsub, osmo_gsm48_classmark_is_r99(&vsub->classmark),
				       msc_a->c.ran->type == OSMO_RAT_UTRAN_IU,
				       res, res_len);
}

static int gsm48_rx_mm_auth_fail(struct msc_a *msc_a, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t cause;
	uint8_t auts_tag;
	uint8_t auts_len;
	uint8_t *auts;
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);

	if (!vsub) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR, "MM R99 AUTHENTICATION FAILURE: invalid: no subscriber\n");
		msc_a_release_mo(msc_a, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	if (msgb_l3len(msg) < sizeof(*gh) + 1) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR, "MM R99 AUTHENTICATION FAILURE: l3 length invalid: %u\n",
			      msgb_l3len(msg));
		msc_a_release_mo(msc_a, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	cause = gh->data[0];

	if (cause != GSM48_REJECT_SYNCH_FAILURE) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_INFO, "MM R99 AUTHENTICATION FAILURE: cause 0x%0x\n", cause);
		vlr_subscr_rx_auth_fail(vsub, NULL);
		return 0;
	}

	/* This is a Synch Failure procedure, which should pass an AUTS to
	 * resynchronize the sequence nr with the HLR. Expecting exactly one
	 * TLV with 14 bytes of AUTS. */

	if (msgb_l3len(msg) < sizeof(*gh) + 1 + 2) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_INFO,
			      "MM R99 AUTHENTICATION FAILURE: invalid Synch Failure: missing AUTS IE\n");
		msc_a_release_mo(msc_a, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	auts_tag = gh->data[1];
	auts_len = gh->data[2];
	auts = &gh->data[3];

	if (auts_tag != GSM48_IE_AUTS
	    || auts_len != 14) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_INFO,
			      "MM R99 AUTHENTICATION FAILURE: invalid Synch Failure:"
			      " expected AUTS IE 0x%02x of 14 bytes,"
			      " got IE 0x%02x of %u bytes\n",
			      GSM48_IE_AUTS, auts_tag, auts_len);
		msc_a_release_mo(msc_a, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	if (msgb_l3len(msg) < sizeof(*gh) + 1 + 2 + auts_len) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_INFO,
			      "MM R99 AUTHENTICATION FAILURE: invalid Synch Failure msg: message truncated (%u)\n",
			      msgb_l3len(msg));
		msc_a_release_mo(msc_a, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	/* We have an AUTS IE with exactly 14 bytes of AUTS and the msgb is
	 * large enough. */

	LOG_MSC_A_CAT(msc_a, DMM, LOGL_DEBUG, "MM R99 AUTHENTICATION SYNCH (AUTS = %s)\n",
		      osmo_hexdump_nospc(auts, 14));

	return vlr_subscr_rx_auth_fail(vsub, auts);
}

static int gsm48_rx_mm_tmsi_reall_compl(struct msc_a *msc_a)
{
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);
	if (!vsub) {
		LOG_MSC_A_CAT(msc_a, DMM, LOGL_ERROR, "Rx MM TMSI Reallocation Complete: invalid: no subscriber\n");
		return -EINVAL;
	}
	LOG_MSC_A_CAT(msc_a, DMM, LOGL_DEBUG, "TMSI Reallocation Completed, new LAI: %s\n", osmo_lai_name(&msc_a->via_cell.lai));
	return vlr_subscr_rx_tmsi_reall_compl(vsub);
}

/* Receive a GSM 04.08 Mobility Management (MM) message */
int gsm0408_rcv_mm(struct msc_a *msc_a, struct msgb *msg)
{
	
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (gsm48_hdr_msg_type(gh)) {
	case GSM48_MT_MM_LOC_UPD_REQUEST:
		rc = mm_rx_loc_upd_req(msc_a, msg);
		break;
	case GSM48_MT_MM_ID_RESP:
		rc = mm_rx_id_resp(msc_a, msg);
		break;
	case GSM48_MT_MM_CM_SERV_REQ:
		rc = gsm48_rx_mm_serv_req(msc_a, msg);
		break;
	case GSM48_MT_MM_STATUS:
		rc = gsm48_rx_mm_status(msg);
		break;
	case GSM48_MT_MM_TMSI_REALL_COMPL:
		rc = gsm48_rx_mm_tmsi_reall_compl(msc_a);
		break;
	case GSM48_MT_MM_IMSI_DETACH_IND:
		rc = gsm48_rx_mm_imsi_detach_ind(msc_a, msg);
		break;
	case GSM48_MT_MM_CM_REEST_REQ:
		rc = gsm48_rx_cm_reest_req(msc_a, msg);
		break;
	case GSM48_MT_MM_AUTH_RESP:
		rc = gsm48_rx_mm_auth_resp(msc_a, msg);
		break;
	case GSM48_MT_MM_AUTH_FAIL:
		rc = gsm48_rx_mm_auth_fail(msc_a, msg);
		break;
	default:
		LOGP(DMM, LOGL_NOTICE, "Unknown GSM 04.08 MM msg type 0x%02x\n",
			gh->msg_type);
		break;
	}

	return rc;
}

/* Receive a PAGING RESPONSE message from the MS */
static int gsm48_rx_rr_pag_resp(struct msc_a *msc_a, struct msgb *msg)
{
	struct gsm_network *net = msc_a_net(msc_a);
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_pag_resp *pr =
			(struct gsm48_pag_resp *)gh->data;
	uint8_t classmark2_len = gh->data[1];
	uint8_t *classmark2_buf = gh->data+2;
	struct gsm48_classmark2 *cm2 = (void*)classmark2_buf;
	bool is_utran;
	struct vlr_subscr *vsub;
	struct osmo_mobile_identity mi;
	int rc;

	if (msc_a_is_establishing_auth_ciph(msc_a)) {
		LOG_MSC_A_CAT(msc_a, DRR, LOGL_ERROR,
			      "Ignoring Paging Response, conn already busy establishing authenticity\n");
		return 0;
	}

	if (msc_a_is_accepted(msc_a)) {
		LOG_MSC_A_CAT(msc_a, DRR, LOGL_ERROR, "Ignoring Paging Response, conn already established\n");
		return 0;
	}

	rc = osmo_mobile_identity_decode_from_l3(&mi, msg, false);
	if (rc) {
		LOG_MSC_A_CAT(msc_a, DRR, LOGL_ERROR, "Paging Response: cannot decode Mobile Identity\n");
		return -EINVAL;
	}

	msc_a->complete_layer3_type = COMPLETE_LAYER3_PAGING_RESP;
	msub_update_id_from_mi(msc_a->c.msub, &mi);
	LOG_MSC_A_CAT(msc_a, DRR, LOGL_DEBUG, "Rx PAGING RESPONSE %s\n", osmo_mobile_identity_to_str_c(OTC_SELECT, &mi));

	msc_a_get(msc_a, MSC_A_USE_PAGING_RESPONSE);

	is_utran = (msc_a->c.ran->type == OSMO_RAT_UTRAN_IU);
	vlr_proc_acc_req(msc_a->c.fi,
			 MSC_A_EV_AUTHENTICATED, MSC_A_EV_CN_CLOSE, NULL,
			 net->vlr, msc_a,
			 VLR_PR_ARQ_T_PAGING_RESP, 0, &mi, &msc_a->via_cell.lai,
			 is_utran || net->authentication_required,
			 is_utran ? net->uea_encryption : net->a5_encryption_mask > 0x01,
			 pr->key_seq,
			 osmo_gsm48_classmark2_is_r99(cm2, classmark2_len),
			 is_utran);

	/* From vlr_proc_acc_req() we expect an implicit dispatch of PR_ARQ_E_START we expect
	 * msc_vlr_subscr_assoc() to already have been called and completed. Has an error occurred? */
	vsub = msc_a_vsub(msc_a);
	if (!vsub) {
		LOG_MSC_A_CAT(msc_a, DRR, LOGL_ERROR, "subscriber not allowed to do a Paging Response\n");

		/* Above MSC_A_USE_PAGING_RESPONSE may already have been removed by a forced release, put that use only
		 * if it still exists. (see msc_a_fsm_releasing_onenter()) */
		if (osmo_use_count_by(&msc_a->use_count, MSC_A_USE_PAGING_RESPONSE))
			msc_a_put(msc_a, MSC_A_USE_PAGING_RESPONSE);

		return -EIO;
	}

	vsub->classmark.classmark2 = *cm2;
	vsub->classmark.classmark2_len = classmark2_len;
	return 0;
}

static int gsm48_rx_rr_ciphering_mode_complete(struct msc_a *msc_a, struct msgb *msg)
{
	struct vlr_subscr *vsub = msc_a_vsub(msc_a);
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct tlv_p_entry *mi_tlv;
	struct osmo_mobile_identity mi;

	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	mi_tlv = TLVP_GET(&tp, GSM48_IE_MOBILE_ID);

	/* IMEI(SV) is optional for this message */
	if (!mi_tlv)
		return 0;
	if (!mi_tlv->len)
		return -EINVAL;

	if (osmo_mobile_identity_decode(&mi, mi_tlv->val, mi_tlv->len, false)) {
		LOGP(DMM, LOGL_ERROR, "RR Ciphering Mode Complete contains invalid Mobile Identity %s\n",
		     osmo_hexdump(mi_tlv->val, mi_tlv->len));
		return -EINVAL;
	}
	if (mi.type != GSM_MI_TYPE_IMEISV) {
		LOGP(DMM, LOGL_ERROR, "RR Ciphering Mode Complete contains "
				      "unexpected Mobile Identity type %s\n",
				      osmo_mobile_identity_to_str_c(OTC_SELECT, &mi));
		return -EINVAL;
	}

	LOG_MSC_A(msc_a, LOGL_DEBUG, "RR Ciphering Mode Complete contains Mobile Identity: %s\n",
		  osmo_mobile_identity_to_str_c(OTC_SELECT, &mi));

	if (!vsub)
		return 0;

	return vlr_subscr_rx_id_resp(vsub, &mi);
}

static int gsm48_rx_rr_app_info(struct msc_a *msc_a, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t apdu_id_flags;
	uint8_t apdu_len;
	uint8_t *apdu_data;

	apdu_id_flags = gh->data[0];
	apdu_len = gh->data[1];
	apdu_data = gh->data+2;

	LOG_MSC_A_CAT(msc_a, DRR, LOGL_DEBUG, "Rx RR APPLICATION INFO "
		      "(id/flags=0x%02x apdu_len=%u apdu=%s)\n",
		      apdu_id_flags, apdu_len, osmo_hexdump(apdu_data, apdu_len));

	/* we're not using the app info blob anywhere, so ignore. */
#if 0
	return db_apdu_blob_store(conn->subscr, apdu_id_flags, apdu_len, apdu_data);
#else
	return 0;
#endif
}

/* Receive a GSM 04.08 Radio Resource (RR) message */
int gsm0408_rcv_rr(struct msc_a *msc_a, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (gh->msg_type) {
	case GSM48_MT_RR_PAG_RESP:
		rc = gsm48_rx_rr_pag_resp(msc_a, msg);
		break;
	case GSM48_MT_RR_CIPH_M_COMPL:
		rc = gsm48_rx_rr_ciphering_mode_complete(msc_a, msg);
		break;
	case GSM48_MT_RR_APP_INFO:
		rc = gsm48_rx_rr_app_info(msc_a, msg);
		break;
	default:
		LOG_MSC_A_CAT(msc_a, DRR, LOGL_NOTICE, "MSC: Unimplemented %s GSM 04.08 RR "
			      "message\n", gsm48_rr_msg_name(gh->msg_type));
		break;
	}

	return rc;
}

int gsm48_send_rr_app_info(struct msc_a *msc_a, uint8_t apdu_id,
			   uint8_t apdu_len, const uint8_t *apdu)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 APP INF");
	struct gsm48_hdr *gh;

	DEBUGP(DRR, "TX APPLICATION INFO id=0x%02x, len=%u\n",
		apdu_id, apdu_len);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 2 + apdu_len);
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_APP_INFO;
	gh->data[0] = apdu_id;
	gh->data[1] = apdu_len;
	memcpy(gh->data+2, apdu, apdu_len);

	return msc_a_tx_dtap_to_i(msc_a, msg);
}

extern int gsm0408_rcv_cc(struct msc_a *msc_a, struct msgb *msg);

/***********************************************************************
 * VLR integration
 ***********************************************************************/

/* VLR asks us to send an authentication request */
static int msc_vlr_tx_auth_req(void *msc_conn_ref, struct vlr_auth_tuple *at,
			       bool send_autn)
{
	struct msc_a *msc_a = msc_conn_ref;
	return gsm48_tx_mm_auth_req(msc_a, at->vec.rand,
				    send_autn? at->vec.autn : NULL,
				    at->key_seq);
}

/* VLR asks us to send an authentication reject */
static int msc_vlr_tx_auth_rej(void *msc_conn_ref)
{
	struct msc_a *msc_a = msc_conn_ref;
	return gsm48_tx_mm_auth_rej(msc_a);
}

/* VLR asks us to transmit an Identity Request of given type */
static int msc_vlr_tx_id_req(void *msc_conn_ref, uint8_t mi_type)
{
	struct msc_a *msc_a = msc_conn_ref;

	/* Store requested MI type, so we can check the response */
	msc_a->mm_id_req_type = mi_type;

	return mm_tx_identity_req(msc_a, mi_type);
}

/* VLR asks us to transmit a Location Update Accept */
static int msc_vlr_tx_lu_acc(void *msc_conn_ref, uint32_t send_tmsi)
{
	struct msc_a *msc_a = msc_conn_ref;
	return gsm0408_loc_upd_acc(msc_a, send_tmsi);
}

/* VLR asks us to transmit a Location Update Reject */
static int msc_vlr_tx_lu_rej(void *msc_conn_ref, enum gsm48_reject_value cause)
{
	struct msc_a *msc_a = msc_conn_ref;
	return gsm0408_loc_upd_rej(msc_a, cause);
}

/* VLR asks us to transmit a CM Service Accept */
int msc_vlr_tx_cm_serv_acc(void *msc_conn_ref, enum osmo_cm_service_type cm_service_type)
{
	struct msc_a *msc_a = msc_conn_ref;
	return msc_gsm48_tx_mm_serv_ack(msc_a);
}

static int msc_vlr_tx_common_id(void *msc_conn_ref)
{
	struct msc_a *msc_a = msc_conn_ref;
	struct ran_msg msg = {
		.msg_type = RAN_MSG_COMMON_ID,
		.common_id = {
			.imsi = msc_a_vsub(msc_a)->imsi,
		},
	};
	return msc_a_ran_down(msc_a, MSC_ROLE_I, &msg);
}

/* VLR asks us to transmit MM info. */
static int msc_vlr_tx_mm_info(void *msc_conn_ref)
{
	struct msc_a *msc_a = msc_conn_ref;
	struct gsm_network *net = msc_a_net(msc_a);
	if (!net->send_mm_info)
		return 0;
	return gsm48_tx_mm_info(msc_a);
}

/* VLR asks us to transmit a CM Service Reject */
static int msc_vlr_tx_cm_serv_rej(void *msc_conn_ref, enum osmo_cm_service_type cm_service_type,
				  enum gsm48_reject_value cause)
{
	struct msc_a *msc_a = msc_conn_ref;
	msc_gsm48_tx_mm_serv_rej(msc_a, cause);
	msc_a_put(msc_a, msc_a_cm_service_type_to_use(cm_service_type));
	return 0;
}

/* VLR informs us that the subscriber data has somehow been modified */
static void msc_vlr_subscr_update(struct vlr_subscr *subscr)
{
	struct msub *msub = msub_for_vsub(subscr);
	LOGVSUBP(LOGL_NOTICE, subscr, "VLR: update for IMSI=%s (MSISDN=%s)%s\n",
		 subscr->imsi, subscr->msisdn, msub ? "" : " (NO CONN!)");
	msub_update_id(msub);
}

/* VLR informs us that the subscriber has been associated with a conn.
 * The subscriber has *not* been authenticated yet, so the vsub should be protected from potentially invalid information
 * from the msc_a. */
static int msc_vlr_subscr_assoc(void *msc_conn_ref,
				 struct vlr_subscr *vsub)
{
	struct msc_a *msc_a = msc_conn_ref;
	struct msub *msub = msc_a->c.msub;
	OSMO_ASSERT(vsub);

	if (msub_set_vsub(msub, vsub))
		return -EINVAL;

	/* FIXME: would be better to modify vsub->* only after the subscriber is authenticated, in
	 * evaluate_acceptance_outcome(conn_accepted == true). */

	vsub->cs.attached_via_ran = msc_a->c.ran->type;

	/* In case we have already received Classmark Information before the VLR Subscriber was
	 * associated with the conn: merge the new Classmark into vsub->classmark. Don't overwrite valid
	 * vsub->classmark with unset classmark, though. */
	osmo_gsm48_classmark_update(&vsub->classmark, &msc_a->temporary_classmark);

	msub_update_id(msub);

	osmo_fsm_inst_dispatch(msc_a->c.fi, MSC_A_EV_COMPLETE_LAYER_3_OK, NULL);
	return 0;
}

/* operations that we need to implement for libvlr */
const struct vlr_ops msc_vlr_ops = {
	.tx_auth_req = msc_vlr_tx_auth_req,
	.tx_auth_rej = msc_vlr_tx_auth_rej,
	.tx_id_req = msc_vlr_tx_id_req,
	.tx_lu_acc = msc_vlr_tx_lu_acc,
	.tx_lu_rej = msc_vlr_tx_lu_rej,
	.tx_cm_serv_acc = msc_vlr_tx_cm_serv_acc,
	.tx_cm_serv_rej = msc_vlr_tx_cm_serv_rej,
	.set_ciph_mode = msc_a_vlr_set_cipher_mode,
	.tx_common_id = msc_vlr_tx_common_id,
	.tx_mm_info = msc_vlr_tx_mm_info,
	.subscr_update = msc_vlr_subscr_update,
	.subscr_assoc = msc_vlr_subscr_assoc,
};

struct msgb *gsm48_create_mm_serv_rej(enum gsm48_reject_value value)
{
	struct msgb *msg;
	struct gsm48_hdr *gh;

	msg = gsm48_msgb_alloc_name("GSM 04.08 SERV REJ");
	if (!msg)
		return NULL;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_REJ;
	gh->data[0] = value;

	return msg;
}

struct msgb *gsm48_create_loc_upd_rej(uint8_t cause)
{
	struct gsm48_hdr *gh;
	struct msgb *msg;

	msg = gsm48_msgb_alloc_name("GSM 04.08 LOC UPD REJ");
	if (!msg)
		return NULL;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_REJECT;
	gh->data[0] = cause;
	return msg;
}
