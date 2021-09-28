/* osmo-bsc API to manage timeslot status: init and switch of dynamic PDCH. */
#pragma once

#include <osmocom/bsc/gsm_data.h>

/* This macro automatically includes a final \n, if omitted. */
#define LOG_TS(ts, level, fmt, args...) do { \
	if (ts->fi) \
		LOGPFSML(ts->fi, level, "%s%s%s" fmt "%s", \
			 ts->pchan_is != ts->pchan_from_config ? "(pchan_is=" : "", \
			 ts->pchan_is != ts->pchan_from_config ? gsm_pchan_name(ts->pchan_is) : "", \
			 ts->pchan_is != ts->pchan_from_config ? ") " : "", \
## args, \
			 (!fmt || !*fmt || fmt[strlen(fmt)-1] != '\n') ? "\n" : ""); \
	else \
		LOGP(DRSL, level, "%s" fmt "%s", \
		     gsm_ts_name(ts), \
		     ## args, \
		     (!fmt || !*fmt || fmt[strlen(fmt)-1] != '\n') ? "\n" : ""); \
	} while(0)

enum ts_fsm_state {
	TS_ST_NOT_INITIALIZED,
	TS_ST_UNUSED,
	TS_ST_WAIT_PDCH_ACT,
	TS_ST_PDCH,
	TS_ST_WAIT_PDCH_DEACT,
	TS_ST_IN_USE,
	TS_ST_BORKEN,
};

enum ts_fsm_event {
	TS_EV_OML_READY,
	TS_EV_OML_DOWN,
	TS_EV_RSL_READY,
	TS_EV_RSL_DOWN,
	TS_EV_LCHAN_REQUESTED,
	TS_EV_LCHAN_UNUSED,
	TS_EV_PDCH_ACT_ACK,
        TS_EV_PDCH_ACT_NACK,
        TS_EV_PDCH_DEACT_ACK,
        TS_EV_PDCH_DEACT_NACK,
};

void ts_fsm_init();

void ts_fsm_alloc(struct gsm_bts_trx_ts *ts);

bool ts_is_capable_of_pchan(struct gsm_bts_trx_ts *ts, enum gsm_phys_chan_config pchan);
bool ts_is_capable_of_lchant(struct gsm_bts_trx_ts *ts, enum gsm_chan_t type);
bool ts_is_lchan_waiting_for_pchan(struct gsm_bts_trx_ts *ts, enum gsm_phys_chan_config *target_pchan);
bool ts_is_pchan_switching(struct gsm_bts_trx_ts *ts, enum gsm_phys_chan_config *target_pchan);
bool ts_usable_as_pchan(struct gsm_bts_trx_ts *ts, enum gsm_phys_chan_config as_pchan, bool allow_pchan_switch);
void ts_setup_lchans(struct gsm_bts_trx_ts *ts);
