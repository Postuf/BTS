/*
 * (C) 2014 by Holger Hans Peter Freyther
 * (C) 2014 by sysmocom s.f.m.c. GmbH
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

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/core/utils.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/db.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/vlr.h>

#include <stdbool.h>

#define VSUB_USE_CTRL "CTRL"

static struct gsm_network *msc_ctrl_net = NULL;

static int get_subscriber_list(struct ctrl_cmd *cmd, void *d)
{
	struct vlr_subscr *vsub;

	if (!msc_ctrl_net) {
		cmd->reply = "MSC CTRL commands not initialized";
		return CTRL_CMD_ERROR;
	}

	if (!msc_ctrl_net->vlr) {
		cmd->reply = "VLR not initialized";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = talloc_strdup(cmd, "");

	llist_for_each_entry(vsub, &msc_ctrl_net->vlr->subscribers, list) {
		/* Do not list subscribers that aren't successfully attached. */
		if (!vsub->lu_complete)
			continue;
		time_t last_seen = -1;
		struct timespec now;
		
		if (osmo_clock_gettime(CLOCK_MONOTONIC, &now) == 0 && vsub->expire_lu) {
		    last_seen = now.tv_sec - (vsub->expire_lu - vlr_timer(vsub->vlr, 3212));
	    }
			

		cmd->reply = talloc_asprintf_append(cmd->reply, "%s,%s,%s,%lu\n",
						    vsub->imsi, vsub->msisdn, vsub->imei, last_seen);
	}
	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(subscriber_list, "subscriber-list-active-v1");

CTRL_CMD_DEFINE_WO_NOVRF(sub_expire, "subscriber-expire");
static int set_sub_expire(struct ctrl_cmd *cmd, void *data)
{
	struct vlr_subscr *vsub;

	if (!msc_ctrl_net) {
		cmd->reply = "MSC CTRL commands not initialized";
		return CTRL_CMD_ERROR;
	}

	if (!msc_ctrl_net->vlr) {
		cmd->reply = "VLR not initialized";
		return CTRL_CMD_ERROR;
	}

	vsub = vlr_subscr_find_by_imsi(msc_ctrl_net->vlr, cmd->value, VSUB_USE_CTRL);
	if (!vsub) {
		LOGP(DCTRL, LOGL_ERROR, "Attempt to expire unknown subscriber IMSI=%s\n", cmd->value);
		cmd->reply = "IMSI unknown";
		return CTRL_CMD_ERROR;
	}

	LOGP(DCTRL, LOGL_NOTICE, "Expiring subscriber IMSI=%s\n", cmd->value);

	if (vlr_subscr_expire(vsub))
		LOGP(DCTRL, LOGL_NOTICE, "VLR released subscriber %s\n", vlr_subscr_name(vsub));

	if (osmo_use_count_total(&vsub->use_count) > 1)
		LOGP(DCTRL, LOGL_NOTICE, "Subscriber %s is still in use, should be released soon\n",
		     vlr_subscr_name(vsub));

	vlr_subscr_put(vsub, VSUB_USE_CTRL);

	return CTRL_CMD_REPLY;
}

int msc_ctrl_cmds_install(struct gsm_network *net)
{
	int rc = 0;
	msc_ctrl_net = net;

	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_subscriber_list);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_sub_expire);

	return rc;
}
