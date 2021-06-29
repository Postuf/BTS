/* Simple HLR/VLR database backend using dbi */
/* (C) 2008 by Jan Luebbe <jluebbe@debian.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <stdint.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <dbi/dbi.h>

#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/gsm_subscriber.h>
#include <osmocom/msc/gsm_04_11.h>
#include <osmocom/msc/db.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/vlr.h>

#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/statistics.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/utils.h>

static char *db_basename = NULL;
static char *db_dirname = NULL;
static dbi_conn conn;
static dbi_inst inst;

#define SCHEMA_REVISION "5"

enum {
	SCHEMA_META,
	INSERT_META,
	SCHEMA_SUBSCRIBER,
	SCHEMA_AUTH,
	SCHEMA_EQUIPMENT,
	SCHEMA_EQUIPMENT_WATCH,
	SCHEMA_SMS,
	SCHEMA_VLR,
	SCHEMA_APDU,
	SCHEMA_COUNTERS,
	SCHEMA_RATE,
	SCHEMA_AUTHKEY,
	SCHEMA_AUTHLAST,
};

static const char *create_stmts[] = {
	[SCHEMA_META] = "CREATE TABLE IF NOT EXISTS Meta ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"key TEXT UNIQUE NOT NULL, "
		"value TEXT NOT NULL"
		")",
	[INSERT_META] = "INSERT OR IGNORE INTO Meta "
		"(key, value) "
		"VALUES "
		"('revision', " SCHEMA_REVISION ")",
	[SCHEMA_SUBSCRIBER] = "CREATE TABLE IF NOT EXISTS Subscriber ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"imsi NUMERIC UNIQUE NOT NULL, "
		"name TEXT, "
		"extension TEXT UNIQUE, "
		"authorized INTEGER NOT NULL DEFAULT 0, "
		"tmsi TEXT UNIQUE, "
		"lac INTEGER NOT NULL DEFAULT 0, "
		"expire_lu TIMESTAMP DEFAULT NULL"
		")",
	[SCHEMA_AUTH] = "CREATE TABLE IF NOT EXISTS AuthToken ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"subscriber_id INTEGER UNIQUE NOT NULL, "
		"created TIMESTAMP NOT NULL, "
		"token TEXT UNIQUE NOT NULL"
		")",
	[SCHEMA_EQUIPMENT] = "CREATE TABLE IF NOT EXISTS Equipment ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"name TEXT, "
		"classmark1 NUMERIC, "
		"classmark2 BLOB, "
		"classmark3 BLOB, "
		"imei NUMERIC UNIQUE NOT NULL"
		")",
	[SCHEMA_EQUIPMENT_WATCH] = "CREATE TABLE IF NOT EXISTS EquipmentWatch ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"subscriber_id NUMERIC NOT NULL, "
		"equipment_id NUMERIC NOT NULL, "
		"UNIQUE (subscriber_id, equipment_id) "
		")",
	[SCHEMA_SMS] = "CREATE TABLE IF NOT EXISTS SMS ("
		/* metadata, not part of sms */
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"sent TIMESTAMP, "
		"deliver_attempts INTEGER NOT NULL DEFAULT 0, "
		/* data directly copied/derived from SMS */
		"valid_until TIMESTAMP, "
		"reply_path_req INTEGER NOT NULL, "
		"status_rep_req INTEGER NOT NULL, "
		"is_report INTEGER NOT NULL, "
		"msg_ref INTEGER NOT NULL, "
		"protocol_id INTEGER NOT NULL, "
		"data_coding_scheme INTEGER NOT NULL, "
		"ud_hdr_ind INTEGER NOT NULL, "
		"src_addr TEXT NOT NULL, "
		"src_ton INTEGER NOT NULL, "
		"src_npi INTEGER NOT NULL, "
		"dest_addr TEXT NOT NULL, "
		"dest_ton INTEGER NOT NULL, "
		"dest_npi INTEGER NOT NULL, "
		"user_data BLOB, "	/* TP-UD */
		/* additional data, interpreted from SMS */
		"header BLOB, "		/* UD Header */
		"text TEXT "		/* decoded UD after UDH */
		")",
	[SCHEMA_VLR] = "CREATE TABLE IF NOT EXISTS VLR ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"subscriber_id NUMERIC UNIQUE NOT NULL, "
		"last_bts NUMERIC NOT NULL "
		")",
	[SCHEMA_APDU] = "CREATE TABLE IF NOT EXISTS ApduBlobs ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"apdu_id_flags INTEGER NOT NULL, "
		"subscriber_id INTEGER NOT NULL, "
		"apdu BLOB "
		")",
	[SCHEMA_COUNTERS] = "CREATE TABLE IF NOT EXISTS Counters ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"timestamp TIMESTAMP NOT NULL, "
		"value INTEGER NOT NULL, "
		"name TEXT NOT NULL "
		")",
	[SCHEMA_RATE] = "CREATE TABLE IF NOT EXISTS RateCounters ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"timestamp TIMESTAMP NOT NULL, "
		"value INTEGER NOT NULL, "
		"name TEXT NOT NULL, "
		"idx INTEGER NOT NULL "
		")",
	[SCHEMA_AUTHKEY] = "CREATE TABLE IF NOT EXISTS AuthKeys ("
		"subscriber_id INTEGER PRIMARY KEY, "
		"algorithm_id INTEGER NOT NULL, "
		"a3a8_ki BLOB "
		")",
	[SCHEMA_AUTHLAST] = "CREATE TABLE IF NOT EXISTS AuthLastTuples ("
		"subscriber_id INTEGER PRIMARY KEY, "
		"issued TIMESTAMP NOT NULL, "
		"use_count INTEGER NOT NULL DEFAULT 0, "
		"key_seq INTEGER NOT NULL, "
		"rand BLOB NOT NULL, "
		"sres BLOB NOT NULL, "
		"kc BLOB NOT NULL "
		")",
};

static inline int next_row(dbi_result result)
{
	if (!dbi_result_has_next_row(result))
		return 0;
	return dbi_result_next_row(result);
}

void db_error_func(dbi_conn conn, void *data)
{
	const char *msg;
	dbi_conn_error(conn, &msg);
	LOGP(DDB, LOGL_ERROR, "DBI: %s\n", msg);
	osmo_log_backtrace(DDB, LOGL_ERROR);
}

static int update_db_revision_2(void)
{
	dbi_result result;

	result = dbi_conn_query(conn,
				"ALTER TABLE Subscriber "
				"ADD COLUMN expire_lu "
				"TIMESTAMP DEFAULT NULL");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to alter table Subscriber (upgrade from rev 2).\n");
		return -EINVAL;
	}
	dbi_result_free(result);

	result = dbi_conn_query(conn,
				"UPDATE Meta "
				"SET value = '3' "
				"WHERE key = 'revision'");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to update DB schema revision  (upgrade from rev 2).\n");
		return -EINVAL;
	}
	dbi_result_free(result);

	return 0;
}

static void parse_tp_ud_from_result(struct gsm_sms *sms, dbi_result result)
{
	const unsigned char *user_data;
	unsigned int user_data_len;
	unsigned int text_len;
	const char *text;

	/* Retrieve TP-UDL (User-Data-Length) in octets (regardless of DCS) */
	user_data_len = dbi_result_get_field_length(result, "user_data");
	if (user_data_len > sizeof(sms->user_data)) {
		LOGP(DDB, LOGL_ERROR,
		     "SMS TP-UD length %u is too big, truncating to %zu\n",
		     user_data_len, sizeof(sms->user_data));
		user_data_len = (uint8_t) sizeof(sms->user_data);
	}
	sms->user_data_len = user_data_len;

	/* Retrieve the TP-UD (User-Data) itself */
	if (user_data_len > 0) {
		user_data = dbi_result_get_binary(result, "user_data");
		memcpy(sms->user_data, user_data, user_data_len);
	}

	/* Retrieve the text length (excluding '\0') */
	text_len = dbi_result_get_field_length(result, "text");
	if (text_len >= sizeof(sms->text)) {
		LOGP(DDB, LOGL_ERROR,
		     "SMS text length %u is too big, truncating to %zu\n",
		     text_len, sizeof(sms->text) - 1);
		/* OSMO_STRLCPY_ARRAY() does truncation for us */
	}

	/* Retrieve the text parsed from TP-UD (User-Data) */
	text = dbi_result_get_string(result, "text");
	if (text)
		OSMO_STRLCPY_ARRAY(sms->text, text);
}

/**
 * Copied from the normal sms_from_result_v3 to avoid having
 * to make sure that the real routine will remain backward
 * compatible.
 */
static struct gsm_sms *sms_from_result_v3(dbi_result result)
{
	struct gsm_sms *sms = sms_alloc();
	long long unsigned int sender_id;
	const char *daddr;
	char buf[32];
	char *quoted;
	dbi_result result2;
	const char *extension;

	if (!sms)
		return NULL;

	sms->id = dbi_result_get_ulonglong(result, "id");

	/* find extension by id, assuming that the subscriber still exists in
	 * the db */
	sender_id = dbi_result_get_ulonglong(result, "sender_id");
	snprintf(buf, sizeof(buf), "%llu", sender_id);

	dbi_conn_quote_string_copy(conn, buf, &quoted);
	result2 = dbi_conn_queryf(conn,
				  "SELECT extension FROM Subscriber "
				  "WHERE id = %s ", quoted);
	free(quoted);
	extension = dbi_result_get_string(result2, "extension");
	if (extension)
		OSMO_STRLCPY_ARRAY(sms->src.addr, extension);
	dbi_result_free(result2);
	/* got the extension */

	sms->reply_path_req = dbi_result_get_ulonglong(result, "reply_path_req");
	sms->status_rep_req = dbi_result_get_ulonglong(result, "status_rep_req");
	sms->ud_hdr_ind = dbi_result_get_ulonglong(result, "ud_hdr_ind");
	sms->protocol_id = dbi_result_get_ulonglong(result, "protocol_id");
	sms->data_coding_scheme = dbi_result_get_ulonglong(result,
						  "data_coding_scheme");

	daddr = dbi_result_get_string(result, "dest_addr");
	if (daddr)
		OSMO_STRLCPY_ARRAY(sms->dst.addr, daddr);

	/* Parse TP-UD, TP-UDL and decoded text */
	parse_tp_ud_from_result(sms, result);

	return sms;
}

static int update_db_revision_3(void)
{
	dbi_result result;
	struct gsm_sms *sms;

	LOGP(DDB, LOGL_NOTICE, "Going to migrate from revision 3\n");

	result = dbi_conn_query(conn, "BEGIN EXCLUSIVE TRANSACTION");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
			"Failed to begin transaction (upgrade from rev 3)\n");
		return -EINVAL;
	}
	dbi_result_free(result);

	/* Rename old SMS table to be able create a new one */
	result = dbi_conn_query(conn, "ALTER TABLE SMS RENAME TO SMS_3");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to rename the old SMS table (upgrade from rev 3).\n");
		goto rollback;
	}
	dbi_result_free(result);

	/* Create new SMS table with all the bells and whistles! */
	result = dbi_conn_query(conn, create_stmts[SCHEMA_SMS]);
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to create a new SMS table (upgrade from rev 3).\n");
		goto rollback;
	}
	dbi_result_free(result);

	/* Cycle through old messages and convert them to the new format */
	result = dbi_conn_query(conn, "SELECT * FROM SMS_3");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed fetch messages from the old SMS table (upgrade from rev 3).\n");
		goto rollback;
	}
	while (next_row(result)) {
		sms = sms_from_result_v3(result);
		if (db_sms_store(sms) != 0) {
			LOGP(DDB, LOGL_ERROR, "Failed to store message to the new SMS table(upgrade from rev 3).\n");
			sms_free(sms);
			dbi_result_free(result);
			goto rollback;
		}
		sms_free(sms);
	}
	dbi_result_free(result);

	/* Remove the temporary table */
	result = dbi_conn_query(conn, "DROP TABLE SMS_3");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to drop the old SMS table (upgrade from rev 3).\n");
		goto rollback;
	}
	dbi_result_free(result);

	/* We're done. Bump DB Meta revision to 4 */
	result = dbi_conn_query(conn,
				"UPDATE Meta "
				"SET value = '4' "
				"WHERE key = 'revision'");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to update DB schema revision (upgrade from rev 3).\n");
		goto rollback;
	}
	dbi_result_free(result);

	result = dbi_conn_query(conn, "COMMIT TRANSACTION");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
			"Failed to commit the transaction (upgrade from rev 3)\n");
		return -EINVAL;
	} else {
		dbi_result_free(result);
	}

	/* Shrink DB file size by actually wiping out SMS_3 table data */
	result = dbi_conn_query(conn, "VACUUM");
	if (!result)
		LOGP(DDB, LOGL_ERROR,
			"VACUUM failed. Ignoring it (upgrade from rev 3).\n");
	else
		dbi_result_free(result);

	return 0;

rollback:
	result = dbi_conn_query(conn, "ROLLBACK TRANSACTION");
	if (!result)
		LOGP(DDB, LOGL_ERROR,
			"Rollback failed (upgrade from rev 3).\n");
	else
		dbi_result_free(result);
	return -EINVAL;
}

/* Just like v3, but there is a new message reference field for status reports,
 * that is set to zero for existing entries since there is no way we can infer
 * this.
 */
static struct gsm_sms *sms_from_result_v4(dbi_result result)
{
	struct gsm_sms *sms = sms_alloc();
	const char *addr;

	if (!sms)
		return NULL;

	sms->id = dbi_result_get_ulonglong(result, "id");

	sms->reply_path_req = dbi_result_get_ulonglong(result, "reply_path_req");
	sms->status_rep_req = dbi_result_get_ulonglong(result, "status_rep_req");
	sms->ud_hdr_ind = dbi_result_get_ulonglong(result, "ud_hdr_ind");
	sms->protocol_id = dbi_result_get_ulonglong(result, "protocol_id");
	sms->data_coding_scheme = dbi_result_get_ulonglong(result,
						  "data_coding_scheme");

	addr = dbi_result_get_string(result, "src_addr");
	OSMO_STRLCPY_ARRAY(sms->src.addr, addr);
	sms->src.ton = dbi_result_get_ulonglong(result, "src_ton");
	sms->src.npi = dbi_result_get_ulonglong(result, "src_npi");

	addr = dbi_result_get_string(result, "dest_addr");
	OSMO_STRLCPY_ARRAY(sms->dst.addr, addr);
	sms->dst.ton = dbi_result_get_ulonglong(result, "dest_ton");
	sms->dst.npi = dbi_result_get_ulonglong(result, "dest_npi");

	/* Parse TP-UD, TP-UDL and decoded text */
	parse_tp_ud_from_result(sms, result);

	return sms;
}

static int update_db_revision_4(void)
{
	dbi_result result;
	struct gsm_sms *sms;

	LOGP(DDB, LOGL_NOTICE, "Going to migrate from revision 4\n");

	result = dbi_conn_query(conn, "BEGIN EXCLUSIVE TRANSACTION");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
			"Failed to begin transaction (upgrade from rev 4)\n");
		return -EINVAL;
	}
	dbi_result_free(result);

	/* Rename old SMS table to be able create a new one */
	result = dbi_conn_query(conn, "ALTER TABLE SMS RENAME TO SMS_4");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to rename the old SMS table (upgrade from rev 4).\n");
		goto rollback;
	}
	dbi_result_free(result);

	/* Create new SMS table with all the bells and whistles! */
	result = dbi_conn_query(conn, create_stmts[SCHEMA_SMS]);
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to create a new SMS table (upgrade from rev 4).\n");
		goto rollback;
	}
	dbi_result_free(result);

	/* Cycle through old messages and convert them to the new format */
	result = dbi_conn_query(conn, "SELECT * FROM SMS_4");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed fetch messages from the old SMS table (upgrade from rev 4).\n");
		goto rollback;
	}
	while (next_row(result)) {
		sms = sms_from_result_v4(result);
		if (db_sms_store(sms) != 0) {
			LOGP(DDB, LOGL_ERROR, "Failed to store message to the new SMS table(upgrade from rev 4).\n");
			sms_free(sms);
			dbi_result_free(result);
			goto rollback;
		}
		sms_free(sms);
	}
	dbi_result_free(result);

	/* Remove the temporary table */
	result = dbi_conn_query(conn, "DROP TABLE SMS_4");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to drop the old SMS table (upgrade from rev 4).\n");
		goto rollback;
	}
	dbi_result_free(result);

	/* We're done. Bump DB Meta revision to 4 */
	result = dbi_conn_query(conn,
				"UPDATE Meta "
				"SET value = '5' "
				"WHERE key = 'revision'");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to update DB schema revision (upgrade from rev 4).\n");
		goto rollback;
	}
	dbi_result_free(result);

	result = dbi_conn_query(conn, "COMMIT TRANSACTION");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
			"Failed to commit the transaction (upgrade from rev 4)\n");
		return -EINVAL;
	} else {
		dbi_result_free(result);
	}

	/* Shrink DB file size by actually wiping out SMS_4 table data */
	result = dbi_conn_query(conn, "VACUUM");
	if (!result)
		LOGP(DDB, LOGL_ERROR,
			"VACUUM failed. Ignoring it (upgrade from rev 4).\n");
	else
		dbi_result_free(result);

	return 0;

rollback:
	result = dbi_conn_query(conn, "ROLLBACK TRANSACTION");
	if (!result)
		LOGP(DDB, LOGL_ERROR,
			"Rollback failed (upgrade from rev 4).\n");
	else
		dbi_result_free(result);
	return -EINVAL;
}

static int check_db_revision(void)
{
	dbi_result result;
	const char *rev_s;
	int db_rev = 0;

	/* Make a query */
	result = dbi_conn_query(conn,
		"SELECT value FROM Meta "
		"WHERE key = 'revision'");

	if (!result)
		return -EINVAL;

	if (!next_row(result)) {
		dbi_result_free(result);
		return -EINVAL;
	}

	/* Fetch the DB schema revision */
	rev_s = dbi_result_get_string(result, "value");
	if (!rev_s) {
		dbi_result_free(result);
		return -EINVAL;
	}

	if (!strcmp(rev_s, SCHEMA_REVISION)) {
		/* Everything is fine */
		dbi_result_free(result);
		return 0;
	}

	db_rev = atoi(rev_s);
	dbi_result_free(result);

	/* Incremental migration waterfall */
	switch (db_rev) {
	case 2:
		if (update_db_revision_2())
			goto error;
	/* fall through */
	case 3:
		if (update_db_revision_3())
			goto error;
	/* fall through */
	case 4:
		if (update_db_revision_4())
			goto error;

	/* The end of waterfall */
	break;
	default:
		LOGP(DDB, LOGL_FATAL,
			"Invalid database schema revision '%d'.\n", db_rev);
		return -EINVAL;
	}

	return 0;

error:
	LOGP(DDB, LOGL_FATAL, "Failed to update database "
		"from schema revision '%d'.\n", db_rev);
	return -EINVAL;
}

static int db_configure(void)
{
	dbi_result result;

	result = dbi_conn_query(conn,
				"PRAGMA synchronous = FULL");
	if (!result)
		return -EINVAL;

	dbi_result_free(result);
	return 0;
}

int db_init(const char *name)
{
	dbi_initialize_r(NULL, &inst);

	LOGP(DDB, LOGL_NOTICE, "Init database connection to '%s' using %s\n",
	     name, dbi_version());

	conn = dbi_conn_new_r("sqlite3", inst);
	if (conn == NULL) {
		LOGP(DDB, LOGL_FATAL, "Failed to create database connection to sqlite3 db '%s'; "
		    "Is the sqlite3 database driver for libdbi installed on this system?\n", name);
		return 1;
	}

	dbi_conn_error_handler( conn, db_error_func, NULL );

	/* MySQL
	dbi_conn_set_option(conn, "host", "localhost");
	dbi_conn_set_option(conn, "username", "your_name");
	dbi_conn_set_option(conn, "password", "your_password");
	dbi_conn_set_option(conn, "dbname", "your_dbname");
	dbi_conn_set_option(conn, "encoding", "UTF-8");
	*/

	/* SqLite 3 */
	db_basename = strdup(name);
	db_dirname = strdup(name);
	dbi_conn_set_option(conn, "sqlite3_dbdir", dirname(db_dirname));
	dbi_conn_set_option(conn, "dbname", basename(db_basename));

	if (dbi_conn_connect(conn) < 0)
		goto out_err;

	return 0;

out_err:
	free(db_dirname);
	free(db_basename);
	db_dirname = db_basename = NULL;
	return -1;
}


int db_prepare(void)
{
	dbi_result result;
	int i;

	for (i = 0; i < ARRAY_SIZE(create_stmts); i++) {
		result = dbi_conn_query(conn, create_stmts[i]);
		if (!result) {
			LOGP(DDB, LOGL_ERROR,
			     "Failed to create some table.\n");
			return 1;
		}
		dbi_result_free(result);
	}

	if (check_db_revision() < 0) {
		LOGP(DDB, LOGL_FATAL, "Database schema revision invalid, "
			"please update your database schema\n");
                return -1;
	}

	db_configure();

	return 0;
}

int db_fini(void)
{
	dbi_conn_close(conn);
	dbi_shutdown_r(inst);

	free(db_dirname);
	free(db_basename);
	return 0;
}

/* store an [unsent] SMS to the database */
int db_sms_store(struct gsm_sms *sms)
{
	dbi_result result;
	char *q_text, *q_daddr, *q_saddr;
	unsigned char *q_udata = NULL;
	time_t now, validity_timestamp;

	dbi_conn_quote_string_copy(conn, (char *)sms->text, &q_text);
	dbi_conn_quote_string_copy(conn, (char *)sms->dst.addr, &q_daddr);
	dbi_conn_quote_string_copy(conn, (char *)sms->src.addr, &q_saddr);

	/* Guard against zero-length input, as this may cause
	 * buffer overruns in libdbi / libdbdsqlite3. */
	if (sms->user_data_len > 0) {
		dbi_conn_quote_binary_copy(conn, sms->user_data,
					   sms->user_data_len,
					   &q_udata);
	}

	now = time(NULL);
	// validity_timestamp = now + sms->validity_minutes * 60;
	validity_timestamp = now + 15; // 15 seconds

	result = dbi_conn_queryf(conn,
		"INSERT INTO SMS "
		"(created, valid_until, "
		 "reply_path_req, status_rep_req, is_report, "
		 "msg_ref, protocol_id, data_coding_scheme, "
		 "ud_hdr_ind, "
		 "user_data, text, "
		 "dest_addr, dest_ton, dest_npi, "
		 "src_addr, src_ton, src_npi) VALUES "
		"(datetime('%lld', 'unixepoch'), datetime('%lld', 'unixepoch'), "
		"%u, %u, %u, "
		"%u, %u, %u, "
		"%u, "
		"%s, %s, "
		"%s, %u, %u, "
		"%s, %u, %u)",
		(int64_t)now, (int64_t)validity_timestamp,
		sms->reply_path_req, sms->status_rep_req, sms->is_report,
		sms->msg_ref, sms->protocol_id, sms->data_coding_scheme,
		sms->ud_hdr_ind,
		q_udata, q_text,
		q_daddr, sms->dst.ton, sms->dst.npi,
		q_saddr, sms->src.ton, sms->src.npi);
	free(q_text);
	free(q_udata);
	free(q_daddr);
	free(q_saddr);

	if (!result)
		return -EIO;

	dbi_result_free(result);

	sms->id = dbi_conn_sequence_last(conn, "id");
	LOGP(DLSMS, LOGL_INFO, "Stored SMS id=%llu in DB\n", sms->id);
	return 0;
}

static struct gsm_sms *sms_from_result(struct gsm_network *net, dbi_result result)
{
	struct gsm_sms *sms = sms_alloc();
	const char *daddr, *saddr;
	time_t validity_timestamp;

	if (!sms)
		return NULL;

	sms->id = dbi_result_get_ulonglong(result, "id");

	sms->created = dbi_result_get_datetime(result, "created");
	validity_timestamp = dbi_result_get_datetime(result, "valid_until");
	sms->validity_minutes = (validity_timestamp - sms->created) / 60;
	/* FIXME: those should all be get_uchar, but sqlite3 is braindead */
	sms->reply_path_req = dbi_result_get_ulonglong(result, "reply_path_req");
	sms->status_rep_req = dbi_result_get_ulonglong(result, "status_rep_req");
	sms->is_report = dbi_result_get_ulonglong(result, "is_report");
	sms->msg_ref = dbi_result_get_ulonglong(result, "msg_ref");
	sms->ud_hdr_ind = dbi_result_get_ulonglong(result, "ud_hdr_ind");
	sms->protocol_id = dbi_result_get_ulonglong(result, "protocol_id");
	sms->data_coding_scheme = dbi_result_get_ulonglong(result,
						  "data_coding_scheme");

	sms->dst.npi = dbi_result_get_ulonglong(result, "dest_npi");
	sms->dst.ton = dbi_result_get_ulonglong(result, "dest_ton");
	daddr = dbi_result_get_string(result, "dest_addr");
	if (daddr)
		OSMO_STRLCPY_ARRAY(sms->dst.addr, daddr);

	if (net != NULL) /* db_sms_test passes NULL, so we need to be tolerant */
		sms->receiver = vlr_subscr_find_by_msisdn(net->vlr, sms->dst.addr,
							  VSUB_USE_SMS_RECEIVER);

	sms->src.npi = dbi_result_get_ulonglong(result, "src_npi");
	sms->src.ton = dbi_result_get_ulonglong(result, "src_ton");
	saddr = dbi_result_get_string(result, "src_addr");
	if (saddr)
		OSMO_STRLCPY_ARRAY(sms->src.addr, saddr);

	/* Parse TP-UD, TP-UDL and decoded text */
	parse_tp_ud_from_result(sms, result);

	return sms;
}

struct gsm_sms *db_sms_get(struct gsm_network *net, unsigned long long id)
{
	dbi_result result;
	struct gsm_sms *sms;

	result = dbi_conn_queryf(conn,
		"SELECT * FROM SMS WHERE SMS.id = %llu", id);
	if (!result)
		return NULL;

	if (!next_row(result)) {
		dbi_result_free(result);
		return NULL;
	}

	sms = sms_from_result(net, result);

	dbi_result_free(result);

	return sms;
}

struct gsm_sms *db_sms_get_next_unsent(struct gsm_network *net,
				       unsigned long long min_sms_id,
				       unsigned int max_failed)
{
	dbi_result result;
	struct gsm_sms *sms;

	result = dbi_conn_queryf(conn,
		"SELECT * FROM SMS"
		" WHERE sent IS NULL"
		" AND id >= %llu"
		" AND deliver_attempts <= %u"
		" ORDER BY id LIMIT 1",
		min_sms_id, max_failed);

	if (!result)
		return NULL;

	if (!next_row(result)) {
		dbi_result_free(result);
		return NULL;
	}

	sms = sms_from_result(net, result);

	dbi_result_free(result);

	return sms;
}

/* retrieve the next unsent SMS for a given subscriber */
struct gsm_sms *db_sms_get_unsent_for_subscr(struct vlr_subscr *vsub,
					     unsigned int max_failed)
{
	struct gsm_network *net = vsub->vlr->user_ctx;
	dbi_result result;
	struct gsm_sms *sms;
	char *q_msisdn;

	if (!vsub->lu_complete)
		return NULL;

	/* A subscriber having no phone number cannot possibly receive SMS. */
	if (*vsub->msisdn == '\0')
		return NULL;

	dbi_conn_quote_string_copy(conn, vsub->msisdn, &q_msisdn);
	result = dbi_conn_queryf(conn,
		"SELECT * FROM SMS"
		" WHERE sent IS NULL"
		" AND dest_addr = %s"
		" AND deliver_attempts <= %u"
		" ORDER BY id LIMIT 1",
		q_msisdn, max_failed);
	free(q_msisdn);

	if (!result)
		return NULL;

	if (!next_row(result)) {
		dbi_result_free(result);
		return NULL;
	}

	sms = sms_from_result(net, result);

	dbi_result_free(result);

	return sms;
}

struct gsm_sms *db_sms_get_next_unsent_rr_msisdn(struct gsm_network *net,
						 const char *last_msisdn,
						 unsigned int max_failed)
{
	dbi_result result;
	struct gsm_sms *sms;
	char *q_last_msisdn;

	dbi_conn_quote_string_copy(conn, last_msisdn, &q_last_msisdn);
	result = dbi_conn_queryf(conn,
		"SELECT * FROM SMS"
		" WHERE sent IS NULL"
		" AND dest_addr > %s"
		" AND deliver_attempts <= %u"
		" ORDER BY dest_addr, id LIMIT 1",
		q_last_msisdn, max_failed);
	free(q_last_msisdn);

	if (!result)
		return NULL;

	if (!next_row(result)) {
		dbi_result_free(result);
		return NULL;
	}

	sms = sms_from_result(net, result);

	dbi_result_free(result);

	return sms;
}

/* mark a given SMS as delivered */
int db_sms_mark_delivered(struct gsm_sms *sms)
{
	dbi_result result;

	result = dbi_conn_queryf(conn,
		"UPDATE SMS "
		"SET sent = datetime('now') "
		"WHERE id = %llu", sms->id);
	if (!result) {
		LOGP(DDB, LOGL_ERROR, "Failed to mark SMS %llu as sent.\n", sms->id);
		return 1;
	}

	dbi_result_free(result);
	return 0;
}

/* increase the number of attempted deliveries */
int db_sms_inc_deliver_attempts(struct gsm_sms *sms)
{
	dbi_result result;

	result = dbi_conn_queryf(conn,
		"UPDATE SMS "
		"SET deliver_attempts = deliver_attempts + 1 "
		"WHERE id = %llu", sms->id);
	if (!result) {
		LOGP(DDB, LOGL_ERROR, "Failed to inc deliver attempts for "
			"SMS %llu.\n", sms->id);
		return 1;
	}

	dbi_result_free(result);
	return 0;
}

/* Drop all pending SMS to or from the given extension */
int db_sms_delete_by_msisdn(const char *msisdn)
{
	dbi_result result;
	char *q_msisdn;
	if (!msisdn || !*msisdn)
		return 0;

	dbi_conn_quote_string_copy(conn, msisdn, &q_msisdn);
	result = dbi_conn_queryf(conn,
		    "DELETE FROM SMS WHERE src_addr=%s OR dest_addr=%s",
		    q_msisdn, q_msisdn);
	free(q_msisdn);

	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to delete SMS for %s\n", msisdn);
		return -1;
	}
	dbi_result_free(result);
	return 0;
}

int db_sms_delete_sent_message_by_id(unsigned long long sms_id)
{
	dbi_result result;

	result = dbi_conn_queryf(conn,
			"DELETE FROM SMS WHERE id = %llu AND sent is NOT NULL",
			 sms_id);
	if (!result) {
		LOGP(DDB, LOGL_ERROR, "Failed to delete SMS %llu.\n", sms_id);
		return 1;
	}

	dbi_result_free(result);
	return 0;
}


static int delete_expired_sms(unsigned long long sms_id, time_t validity_timestamp)
{
	dbi_result result;
	time_t now;

	now = time(NULL);

	/* Net yet expired */
	if (validity_timestamp > now)
		return -1;

	result = dbi_conn_queryf(conn, "DELETE FROM SMS WHERE id = %llu", sms_id);
	if (!result) {
		LOGP(DDB, LOGL_ERROR, "Failed to delete SMS %llu.\n", sms_id);
		return -1;
	}
	dbi_result_free(result);
	return 0;
}

int db_sms_delete_expired_message_by_id(unsigned long long sms_id)
{
	dbi_result result;
	time_t validity_timestamp;

	result = dbi_conn_queryf(conn, "SELECT valid_until FROM SMS WHERE id = %llu", sms_id);
	if (!result)
		return -1;
	if (!next_row(result)) {
		dbi_result_free(result);
		return -1;
	}

	validity_timestamp = dbi_result_get_datetime(result, "valid_until");

	dbi_result_free(result);
	return delete_expired_sms(sms_id, validity_timestamp);
}

void db_sms_delete_oldest_expired_message(void)
{
	dbi_result result;

	result = dbi_conn_queryf(conn, "SELECT id,valid_until FROM SMS "
				       "ORDER BY valid_until LIMIT 1");
	if (!result)
		return;

	if (next_row(result)) {
		unsigned long long sms_id;
		time_t validity_timestamp;

		sms_id = dbi_result_get_ulonglong(result, "id");
		validity_timestamp = dbi_result_get_datetime(result, "valid_until");
		delete_expired_sms(sms_id, validity_timestamp);
	}

	dbi_result_free(result);
}
