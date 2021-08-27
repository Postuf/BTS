#pragma once

#include <osmocom/core/linuxlist.h>

struct msc_a;
struct vlr_subscr;
struct gsm_trans;

/* Modeled after the RANAP PagingCause; translates to enum sgsap_service_ind and BSSMAP Channel Needed (3GPP TS 48.008
 * 3.2.2.36) by collapsing e.g. all call related paging causes to SGSAP_SERV_IND_CS_CALL, etc. */
enum paging_cause {
	PAGING_CAUSE_CALL_CONVERSATIONAL = 0,
	PAGING_CAUSE_CALL_STREAMING,
	PAGING_CAUSE_CALL_INTERACTIVE,
	PAGING_CAUSE_CALL_BACKGROUND,
	PAGING_CAUSE_SIGNALLING_LOW_PRIO,
	PAGING_CAUSE_SIGNALLING_HIGH_PRIO,
	PAGING_CAUSE_UNSPECIFIED,
};

extern const struct value_string paging_cause_names[];
static inline const char *paging_cause_name(enum paging_cause val)
{ return get_value_string(paging_cause_names, val); }

/* A successful Paging will pass a valid msc_a, an expired paging will pass msc_a == NULL. */
typedef void (* paging_cb_t )(struct msc_a *msc_a, struct gsm_trans *trans);

struct paging_request {
       struct llist_head entry;

       struct llist_head queue;

       /* human readable label to be able to log pending request kinds */
       const char *label;
       enum paging_cause cause;

       /* the callback data */
       paging_cb_t paging_cb;
       struct gsm_trans *trans;
       struct vlr_subscr *vsub;
};

struct paging_request *paging_request_start(struct vlr_subscr *vsub, enum paging_cause cause,
					    paging_cb_t paging_cb, struct gsm_trans *trans,
					    const char *label);
void paging_request_remove(struct paging_request *pr);

void paging_response(struct msc_a *msc_a);
void paging_expired(struct vlr_subscr *vsub);
