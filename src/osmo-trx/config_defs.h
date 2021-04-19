#pragma once

/*
 * This file contains structures used by both VTY (C, dir CommonLibs) and
 * osmo-trx (CXX, dir Transceiver52)
 */

#include <stdbool.h>

enum FillerType {
  FILLER_DUMMY,
  FILLER_ZERO,
  FILLER_NORM_RAND,
  FILLER_EDGE_RAND,
  FILLER_ACCESS_RAND,
};

enum ReferenceType {
  REF_INTERNAL,
  REF_EXTERNAL,
  REF_GPS,
};

/* Maximum number of physical RF channels */
#define TRX_CHAN_MAX 8

struct trx_ctx;

struct trx_chan {
	struct trx_ctx *trx; /* backpointer */
	unsigned int idx; /* channel index */
	char *rx_path;
	char *tx_path;
};

struct trx_cfg {
	char *bind_addr;
	char *remote_addr;
	char *dev_args;
	unsigned int base_port;
	unsigned int tx_sps;
	unsigned int rx_sps;
	unsigned int rtsc;
	unsigned int rach_delay;
	enum ReferenceType clock_ref;
	enum FillerType filler;
	bool multi_arfcn;
	double offset;
	double freq_offset_khz;
	double rssi_offset;
	bool force_rssi_offset; /* Force value set in VTY? */
	bool swap_channels;
	bool ext_rach;
	bool egprs;
	unsigned int sched_rr;
	unsigned int stack_size;
	unsigned int num_chans;
	struct trx_chan chans[TRX_CHAN_MAX];
	unsigned int vty_port;
	unsigned int ctrl_port;
};
