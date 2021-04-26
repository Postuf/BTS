/*
* Copyright 2018 sysmocom - s.f.m.c. GmbH
*
* SPDX-License-Identifier: AGPL-3.0+
*
* This software is distributed under multiple licenses; see the COPYING file in
* the main directory for licensing information for this specific distribution.
*
* This use of this software may be subject to additional restrictions.
* See the LEGAL file in the main directory for details.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

*/

#ifndef _LMS_DEVICE_H_
#define _LMS_DEVICE_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "radioDevice.h"
#include "smpl_buf.h"

#include <sys/time.h>
#include <math.h>
#include <limits.h>
#include <string>
#include <iostream>
#include <lime/LimeSuite.h>

extern "C" {
#include <osmocom/gsm/gsm_utils.h>
}

/* Definition of LIMESDR_TX_AMPL limits maximum amplitude of I and Q
 * channels separately. Hence LIMESDR_TX_AMPL value must be 1/sqrt(2) =
 * 0.7071.... to get an amplitude of 1 of the complex signal:
 * 	A^2 = I^2 + Q^2
 * 	A^2 = (1/sqrt(2))^2 + (1/sqrt(2))^2
 * 	A^2 = 1/2 + 1/2
 * 	A^2 = 1 */
#define LIMESDR_TX_AMPL  0.707

/* Maximum number of physical RF channels */
#define LIMESDR_TRX_CHAN_MAX  2

enum lms_dev_type {
	LMS_DEV_SDR_USB,   /* LimeSDR-USB */
	LMS_DEV_SDR_MINI,  /* LimeSDR-Mini */
	LMS_DEV_NET_MICRO, /* LimeNet-micro */
	LMS_DEV_UNKNOWN,
};

struct dev_band_desc {
	/* Maximum LimeSuite Tx Gain which can be set/used without distorting
	   the output * signal, and the resulting real output power measured
	   when that gain is used.
	 */
	double nom_lms_tx_gain;  /* dB */
	double nom_out_tx_power; /* dBm */
	/* Factor used to infer base real RSSI offset on the Rx path based on current
	   configured RxGain. The resulting rssiOffset is added to the per burst
	   calculated energy in upper layers. These values were empirically
	   found and may change based on multiple factors, see OS#4468.
	   Correct measured values only provided for LimeSDR-USB so far.
	   rssiOffset = rxGain + rxgain2rssioffset_rel;
	*/
	double rxgain2rssioffset_rel; /* dB */
};

/** A class to handle a LimeSuite supported device */
class LMSDevice:public RadioDevice {

private:
	lms_device_t *m_lms_dev;
	std::vector<lms_stream_t> m_lms_stream_rx;
	std::vector<lms_stream_t> m_lms_stream_tx;

	std::vector<smpl_buf *> rx_buffers;

	double actualSampleRate;	///< the actual USRP sampling rate

	bool started;		///< flag indicates LMS has started
	bool skipRx;		///< set if LMS is transmit-only.

	TIMESTAMP ts_initial, ts_offset;

	std::vector<double> tx_gains, rx_gains;
	enum gsm_band band;
	struct dev_band_desc band_desc;

	enum lms_dev_type m_dev_type;

	int phy_chans[LIMESDR_TRX_CHAN_MAX];

	bool do_calib(size_t chan);
	bool do_filters(size_t chan);
	void log_ant_list(bool dir_tx, size_t chan, std::ostringstream& os);
	int get_ant_idx(const std::string & name, bool dir_tx, size_t chan);
	bool flush_recv(size_t num_pkts);
	void update_stream_stats_rx(size_t chan, bool *overrun);
	void update_stream_stats_tx(size_t chan, bool *underrun);
	bool do_clock_src_freq(enum ReferenceType ref, double freq);
	void get_dev_band_desc(dev_band_desc& desc);
	bool set_band(enum gsm_band req_band);
	void assign_band_desc(enum gsm_band req_band);
public:

	/** Object constructor */
	LMSDevice(size_t tx_sps, size_t rx_sps, InterfaceType iface, size_t chan_num, double lo_offset,
		  const std::vector<std::string>& tx_paths,
		  const std::vector<std::string>& rx_paths);
	~LMSDevice();

	/** Instantiate the LMS */
	int open(const std::string &args, int ref, bool swap_channels);

	/** Start the LMS */
	bool start();

	/** Stop the LMS */
	bool stop();

	enum TxWindowType getWindowType() {
		return TX_WINDOW_LMS1;
	}

	/**
	Read samples from the LMS.
	@param buf preallocated buf to contain read result
	@param len number of samples desired
	@param overrun Set if read buffer has been overrun, e.g. data not being read fast enough
	@param timestamp The timestamp of the first samples to be read
	@param underrun Set if LMS does not have data to transmit, e.g. data not being sent fast enough
	@return The number of samples actually read
	*/
	int readSamples(std::vector < short *>&buf, int len, bool * overrun,
			TIMESTAMP timestamp = 0xffffffff, bool * underrun =
			NULL);
	/**
	Write samples to the LMS.
	@param buf Contains the data to be written.
	@param len number of samples to write.
	@param underrun Set if LMS does not have data to transmit, e.g. data not being sent fast enough
	@param timestamp The timestamp of the first sample of the data buffer.
	@return The number of samples actually written
	*/
	int writeSamples(std::vector < short *>&bufs, int len, bool * underrun,
			 TIMESTAMP timestamp = 0xffffffff);

	/** Update the alignment between the read and write timestamps */
	bool updateAlignment(TIMESTAMP timestamp);

	/** Set the transmitter frequency */
	bool setTxFreq(double wFreq, size_t chan = 0);

	/** Set the receiver frequency */
	bool setRxFreq(double wFreq, size_t chan = 0);

	/** Returns the starting write Timestamp*/
	TIMESTAMP initialWriteTimestamp(void) {
		return ts_initial;
	}

	/** Returns the starting read Timestamp*/
	TIMESTAMP initialReadTimestamp(void) {
		return ts_initial;
	}

	/** returns the full-scale transmit amplitude **/
	double fullScaleInputValue() {
		return(double) SHRT_MAX * LIMESDR_TX_AMPL;
	}

	/** returns the full-scale receive amplitude **/
	double fullScaleOutputValue() {
		return (double) SHRT_MAX;
	}

	/** sets the receive chan gain, returns the gain setting **/
	double setRxGain(double dB, size_t chan = 0);

	/** get the current receive gain */
	double getRxGain(size_t chan = 0) {
		return rx_gains[chan];
	}

	/** return maximum Rx Gain **/
	double maxRxGain(void);

	/** return minimum Rx Gain **/
	double minRxGain(void);

	double rssiOffset(size_t chan);

	double setPowerAttenuation(int atten, size_t chan);
	double getPowerAttenuation(size_t chan = 0);

	int getNominalTxPower(size_t chan = 0);

	/** sets the RX path to use, returns true if successful and false otherwise */
	bool setRxAntenna(const std::string & ant, size_t chan = 0);

	/* return the used RX path */
	std::string getRxAntenna(size_t chan = 0);

	/** sets the RX path to use, returns true if successful and false otherwise */
	bool setTxAntenna(const std::string & ant, size_t chan = 0);

	/* return the used RX path */
	std::string getTxAntenna(size_t chan = 0);

	/** return whether user drives synchronization of Tx/Rx of USRP */
        bool requiresRadioAlign();

        /** return whether user drives synchronization of Tx/Rx of USRP */
        virtual GSM::Time minLatency();

	/** Return internal status values */
	inline double getTxFreq(size_t chan = 0) {
		return 0;
	}
	inline double getRxFreq(size_t chan = 0) {
		return 0;
	}
	inline double getSampleRate() {
		return actualSampleRate;
	}
};

#endif // _LMS_DEVICE_H_
