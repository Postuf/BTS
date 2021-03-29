/*
* Copyright 2018 sysmocom - s.f.m.c. GmbH
*
* SPDX-License-Identifier: AGPL-3.0+
*
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <map>

#include "Logger.h"
#include "Threads.h"
#include "LMSDevice.h"
#include "Utils.h"

#include <lime/LimeSuite.h>

extern "C" {
#include "trx_vty.h"
#include "osmo_signal.h"
#include <osmocom/core/utils.h>
}

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define MAX_ANTENNA_LIST_SIZE 10
#define GSM_CARRIER_BW 270000.0 /* 270kHz */
#define LMS_MIN_BW_SUPPORTED 2.5e6 /* 2.5mHz, minimum supported by LMS */
#define LMS_CALIBRATE_BW_HZ OSMO_MAX(GSM_CARRIER_BW, LMS_MIN_BW_SUPPORTED)
#define SAMPLE_BUF_SZ    (1 << 20) /* Size of Rx timestamp based Ring buffer, in bytes */


/* Device Name Prefixes as presented by LimeSuite API LMS_GetDeviceInfo(): */
#define LMS_DEV_SDR_USB_PREFIX_NAME "LimeSDR-USB"
#define LMS_DEV_SDR_MINI_PREFIX_NAME "LimeSDR-Mini"
#define LMS_DEV_NET_MICRO_PREFIX_NAME "LimeNET-Micro"

/* Device parameter descriptor */
struct dev_desc {
	/* Does LimeSuite allow switching the clock source for this device?
	 * LimeSDR-Mini does not have switches but needs soldering to select
	 * external/internal clock. Any call to LMS_SetClockFreq() will fail.
	 */
	bool clock_src_switchable;
	/* Does LimeSuite allow using REF_INTERNAL for this device?
	 * LimeNET-Micro does not like selecting internal clock
	 */
	bool clock_src_int_usable;
	/* Sample rate coef (without having TX/RX samples per symbol into account) */
	double rate;
	/* Sample rate coef (without having TX/RX samples per symbol into account), if multi-arfcn is enabled */
	double rate_multiarfcn;
	/* Coefficient multiplied by TX sample rate in order to shift Tx time */
	double ts_offset_coef;
	/* Coefficient multiplied by TX sample rate in order to shift Tx time, if multi-arfcn is enabled */
	double ts_offset_coef_multiarfcn;
	/* Device Name Prefix as presented by LimeSuite API LMS_GetDeviceInfo() */
	std::string name_prefix;
};

static const std::map<enum lms_dev_type, struct dev_desc> dev_param_map {
	{ LMS_DEV_SDR_USB,   { true,  true,  GSMRATE, MCBTS_SPACING, 8.9e-5, 7.9e-5, LMS_DEV_SDR_USB_PREFIX_NAME } },
	{ LMS_DEV_SDR_MINI,  { false, true,  GSMRATE, MCBTS_SPACING, 8.9e-5, 8.2e-5, LMS_DEV_SDR_MINI_PREFIX_NAME } },
	{ LMS_DEV_NET_MICRO, { true,  false, GSMRATE, MCBTS_SPACING, 8.9e-5, 7.9e-5, LMS_DEV_NET_MICRO_PREFIX_NAME } },
	{ LMS_DEV_UNKNOWN,   { true,  true,  GSMRATE, MCBTS_SPACING, 8.9e-5, 7.9e-5, "UNKNOWN" } },
};

typedef std::tuple<lms_dev_type, enum gsm_band> dev_band_key;
typedef std::map<dev_band_key, dev_band_desc>::const_iterator dev_band_map_it;
static const std::map<dev_band_key, dev_band_desc> dev_band_nom_power_param_map {
	{ std::make_tuple(LMS_DEV_SDR_USB, GSM_BAND_850),	{ 73.0, 11.2,  -6.0  } },
	{ std::make_tuple(LMS_DEV_SDR_USB, GSM_BAND_900),	{ 73.0, 10.8,  -6.0  } },
	{ std::make_tuple(LMS_DEV_SDR_USB, GSM_BAND_1800),	{ 65.0, -3.5,  -17.0 } }, /* FIXME: OS#4583: 1800Mhz is failing above TxGain=65, which is around -3.5dBm (already < 0 dBm) */
	{ std::make_tuple(LMS_DEV_SDR_USB, GSM_BAND_1900),	{ 73.0, 1.7,   -17.0 } }, /* FIXME: OS#4583: 1900MHz is failing in all TxGain values */
	{ std::make_tuple(LMS_DEV_SDR_MINI, GSM_BAND_850),	{ 66.0, 3.1,   -6.0  } }, /* FIXME: OS#4583: Ensure BAND2 is used at startup */
	{ std::make_tuple(LMS_DEV_SDR_MINI, GSM_BAND_900),	{ 66.0, 2.8,   -6.0  } }, /* FIXME: OS#4583: Ensure BAND2 is used at startup */
	{ std::make_tuple(LMS_DEV_SDR_MINI, GSM_BAND_1800),	{ 66.0, -11.6, -17.0 } }, /* OS#4583: Any of BAND1 or BAND2 is fine */
	{ std::make_tuple(LMS_DEV_SDR_MINI, GSM_BAND_1900),	{ 66.0, -9.2,  -17.0 } }, /* FIXME: OS#4583: Ensure BAND1 is used at startup */
	{ std::make_tuple(LMS_DEV_NET_MICRO, GSM_BAND_850),	{ 71.0, 6.8,   -6.0  } },
	{ std::make_tuple(LMS_DEV_NET_MICRO, GSM_BAND_900),	{ 71.0, 6.8,   -6.0  } },
	{ std::make_tuple(LMS_DEV_NET_MICRO, GSM_BAND_1800),	{ 65.0, -10.5, -17.0 } }, /* OS#4583: TxGain=71 (-4.4dBm) FAIL rms phase errors ~10° */
	{ std::make_tuple(LMS_DEV_NET_MICRO, GSM_BAND_1900),	{ 71.0, -6.3,  -17.0 } }, /* FIXME: OS#4583: all FAIL, BAND1/BAND2 rms phase errors >23° */
};

/* So far measurements done for B210 show really close to linear relationship
 * between gain and real output power, so we simply adjust the measured offset
 */
static double TxGain2TxPower(const dev_band_desc &desc, double tx_gain_db)
{
	return desc.nom_out_tx_power - (desc.nom_lms_tx_gain - tx_gain_db);
}
static double TxPower2TxGain(const dev_band_desc &desc, double tx_power_dbm)
{
	return desc.nom_lms_tx_gain - (desc.nom_out_tx_power - tx_power_dbm);
}

static enum lms_dev_type parse_dev_type(lms_device_t *m_lms_dev)
{
	std::map<enum lms_dev_type, struct dev_desc>::const_iterator it = dev_param_map.begin();

	const lms_dev_info_t* device_info = LMS_GetDeviceInfo(m_lms_dev);

	while (it != dev_param_map.end())
	{
		enum lms_dev_type dev_type = it->first;
		struct dev_desc desc = it->second;

		if (strncmp(device_info->deviceName, desc.name_prefix.c_str(), desc.name_prefix.length()) == 0) {
			LOGC(DDEV, INFO) << "Device identified as " << desc.name_prefix;
			return dev_type;
		}
		it++;
	}
	return LMS_DEV_UNKNOWN;
}

LMSDevice::LMSDevice(size_t tx_sps, size_t rx_sps, InterfaceType iface, size_t chan_num, double lo_offset,
		     const std::vector<std::string>& tx_paths,
		     const std::vector<std::string>& rx_paths):
	RadioDevice(tx_sps, rx_sps, iface, chan_num, lo_offset, tx_paths, rx_paths),
	m_lms_dev(NULL), started(false), band((enum gsm_band)0), m_dev_type(LMS_DEV_UNKNOWN)
{
	LOGC(DDEV, INFO) << "creating LMS device...";

	m_lms_stream_rx.resize(chans);
	m_lms_stream_tx.resize(chans);
	rx_gains.resize(chans);
	tx_gains.resize(chans);

	rx_buffers.resize(chans);

	/* Set up per-channel Rx timestamp based Ring buffers */
	for (size_t i = 0; i < rx_buffers.size(); i++)
		rx_buffers[i] = new smpl_buf(SAMPLE_BUF_SZ / sizeof(uint32_t));

}

LMSDevice::~LMSDevice()
{
	unsigned int i;
	LOGC(DDEV, INFO) << "Closing LMS device";
	if (m_lms_dev) {
		/* disable all channels */
		for (i=0; i<chans; i++) {
			LMS_EnableChannel(m_lms_dev, LMS_CH_RX, i, false);
			LMS_EnableChannel(m_lms_dev, LMS_CH_TX, i, false);
		}
		LMS_Close(m_lms_dev);
		m_lms_dev = NULL;
	}

	for (size_t i = 0; i < rx_buffers.size(); i++)
		delete rx_buffers[i];
}

static void lms_log_callback(int lvl, const char *msg)
{
	/* map lime specific log levels */
	static const int lvl_map[5] = {
		[0] = LOGL_FATAL,
		[LMS_LOG_ERROR] = LOGL_ERROR,
		[LMS_LOG_WARNING] = LOGL_NOTICE,
		[LMS_LOG_INFO] = LOGL_INFO,
		[LMS_LOG_DEBUG] = LOGL_DEBUG,
	};
	/* protect against future higher log level values (lower importance) */
	if ((unsigned int) lvl >= ARRAY_SIZE(lvl_map))
		lvl = ARRAY_SIZE(lvl_map)-1;

	LOGLV(DDEVDRV, lvl_map[lvl]) << msg;
}

static void print_range(const char* name, lms_range_t *range)
{
	LOGC(DDEV, INFO) << name << ": Min=" << range->min << " Max=" << range->max
		   << " Step=" << range->step;
}

/*! Find the device string that matches all filters from \a args.
 *  \param[in] info_list device addresses found by LMS_GetDeviceList()
 *  \param[in] count length of info_list
 *  \param[in] args dev-args value from osmo-trx.cfg, containing comma separated key=value pairs
 *  \return index of first matching device or -1 (no match) */
int info_list_find(lms_info_str_t* info_list, unsigned int count, const std::string &args)
{
	unsigned int i, j;
	std::vector<std::string> filters;

	filters = comma_delimited_to_vector(args.c_str());

	/* iterate over device addresses */
	for (i=0; i < count; i++) {
		/* check if all filters match */
		bool match = true;
		for (j=0; j < filters.size(); j++) {
			if (!strstr(info_list[i], filters[j].c_str())) {
				match = false;
				break;
			}
		}

		if (match)
			return i;
	}
	return -1;
}

void LMSDevice::assign_band_desc(enum gsm_band req_band)
{
	dev_band_map_it it;

	it = dev_band_nom_power_param_map.find(dev_band_key(m_dev_type, req_band));
	if (it == dev_band_nom_power_param_map.end()) {
		dev_desc desc = dev_param_map.at(m_dev_type);
		LOGC(DDEV, ERROR) << "No Tx Power measurements exist for device "
				    << desc.name_prefix << " on band " << gsm_band_name(req_band)
				    << ", using LimeSDR-USB ones as fallback";
		it = dev_band_nom_power_param_map.find(dev_band_key(LMS_DEV_SDR_USB, req_band));
	}
	OSMO_ASSERT(it != dev_band_nom_power_param_map.end());
	band_desc = it->second;
}

bool LMSDevice::set_band(enum gsm_band req_band)
{
	if (band != 0 && req_band != band) {
		LOGC(DDEV, ALERT) << "Requesting band " << gsm_band_name(req_band)
				  << " different from previous band " << gsm_band_name(band);
		return false;
	}

	band = req_band;
	assign_band_desc(band);
	return true;
}

void LMSDevice::get_dev_band_desc(dev_band_desc& desc)
{
	if (band == 0) {
		LOGC(DDEV, ERROR) << "Power parameters requested before Tx Frequency was set! Providing band 900 by default...";
		assign_band_desc(GSM_BAND_900);
	}
	desc = band_desc;
}

int LMSDevice::open(const std::string &args, int ref, bool swap_channels)
{
	lms_info_str_t* info_list;
	lms_range_t range_sr;
	float_type sr_host, sr_rf;
	unsigned int i, n;
	int rc, dev_id;
	struct dev_desc dev_desc;

	LOGC(DDEV, INFO) << "Opening LMS device..";

	LMS_RegisterLogHandler(&lms_log_callback);

	if ((n = LMS_GetDeviceList(NULL)) < 0)
		LOGC(DDEV, ERROR) << "LMS_GetDeviceList(NULL) failed";
	LOGC(DDEV, INFO) << "Devices found: " << n;
	if (n < 1)
	    return -1;

	info_list = new lms_info_str_t[n];

	if (LMS_GetDeviceList(info_list) < 0)
		LOGC(DDEV, ERROR) << "LMS_GetDeviceList(info_list) failed";

	for (i = 0; i < n; i++)
		LOGC(DDEV, INFO) << "Device [" << i << "]: " << info_list[i];

	dev_id = info_list_find(info_list, n, args);
	if (dev_id == -1) {
		LOGC(DDEV, ERROR) << "No LMS device found with address '" << args << "'";
		delete[] info_list;
		return -1;
	}

	LOGC(DDEV, INFO) << "Using device[" << dev_id << "]";
	rc = LMS_Open(&m_lms_dev, info_list[dev_id], NULL);
	if (rc != 0) {
		LOGC(DDEV, ERROR) << "LMS_GetDeviceList() failed)";
		delete [] info_list;
		return -1;
	}

	delete [] info_list;

	m_dev_type = parse_dev_type(m_lms_dev);
	dev_desc = dev_param_map.at(m_dev_type);

	if ((ref != REF_EXTERNAL) && (ref != REF_INTERNAL)){
		LOGC(DDEV, ERROR) << "Invalid reference type";
		goto out_close;
	}

	/* if reference clock is external, setup must happen _before_ calling LMS_Init */
	if (ref == REF_EXTERNAL) {
		LOGC(DDEV, INFO) << "Setting External clock reference to 10MHz";
		/* FIXME: Assume an external 10 MHz reference clock. make
		   external reference frequency configurable */
		if (!do_clock_src_freq(REF_EXTERNAL, 10000000.0))
			goto out_close;
	}

	LOGC(DDEV, INFO) << "Init LMS device";
	if (LMS_Init(m_lms_dev) != 0) {
		LOGC(DDEV, ERROR) << "LMS_Init() failed";
		goto out_close;
	}

	/* if reference clock is internal, setup must happen _after_ calling LMS_Init */
	if (ref == REF_INTERNAL) {
		LOGC(DDEV, INFO) << "Setting Internal clock reference";
		/* Internal freq param is not used */
		if (!do_clock_src_freq(REF_INTERNAL, 0))
			goto out_close;
	}

	/* enable all used channels */
	for (i=0; i<chans; i++) {
		if (LMS_EnableChannel(m_lms_dev, LMS_CH_RX, i, true) < 0)
			goto out_close;
		if (LMS_EnableChannel(m_lms_dev, LMS_CH_TX, i, true) < 0)
			goto out_close;
	}

	/* set samplerate */
	if (LMS_GetSampleRateRange(m_lms_dev, LMS_CH_RX, &range_sr))
		goto out_close;
	print_range("Sample Rate", &range_sr);

	if (iface == MULTI_ARFCN)
		sr_host = dev_desc.rate_multiarfcn * tx_sps;
	else
		sr_host = dev_desc.rate * tx_sps;
	LOGC(DDEV, INFO) << "Setting sample rate to " << sr_host << " " << tx_sps;
	if (LMS_SetSampleRate(m_lms_dev, sr_host, 32) < 0)
		goto out_close;

	if (LMS_GetSampleRate(m_lms_dev, LMS_CH_RX, 0, &sr_host, &sr_rf))
		goto out_close;
	LOGC(DDEV, INFO) << "Sample Rate: Host=" << sr_host << " RF=" << sr_rf;

	if (iface == MULTI_ARFCN)
		ts_offset = static_cast<TIMESTAMP>(dev_desc.ts_offset_coef_multiarfcn * sr_host);
	else
		ts_offset = static_cast<TIMESTAMP>(dev_desc.ts_offset_coef * sr_host);

	/* configure antennas */
	if (!set_antennas()) {
		LOGC(DDEV, FATAL) << "LMS antenna setting failed";
		goto out_close;
	}

	return iface == MULTI_ARFCN ? MULTI_ARFCN : NORMAL;

out_close:
	LOGC(DDEV, FATAL) << "Error in LMS open, closing: " << LMS_GetLastErrorMessage();
	LMS_Close(m_lms_dev);
	m_lms_dev = NULL;
	return -1;
}

bool LMSDevice::start()
{
	LOGC(DDEV, INFO) << "starting LMS...";

	unsigned int i;
	dev_band_desc desc;

	if (started) {
		LOGC(DDEV, ERR) << "Device already started";
		return false;
	}

	get_dev_band_desc(desc);

	/* configure the channels/streams */
	for (i=0; i<chans; i++) {
		/* Set gains for calibration/filter setup */
		/* TX gain to maximum */
		LMS_SetGaindB(m_lms_dev, LMS_CH_TX, i, TxPower2TxGain(desc, desc.nom_out_tx_power));
		/* RX gain to midpoint */
		setRxGain((minRxGain() + maxRxGain()) / 2, i);

		/* set up Rx and Tx filters */
		if (!do_filters(i))
			return false;
		/* Perform Rx and Tx calibration */
		if (!do_calib(i))
			return false;

		/* configure Streams */
		m_lms_stream_rx[i] = {};
		m_lms_stream_rx[i].isTx = false;
		m_lms_stream_rx[i].channel = i;
		m_lms_stream_rx[i].fifoSize = 1024 * 1024;
		m_lms_stream_rx[i].throughputVsLatency = 0.3;
		m_lms_stream_rx[i].dataFmt = lms_stream_t::LMS_FMT_I16;

		m_lms_stream_tx[i] = {};
		m_lms_stream_tx[i].isTx = true;
		m_lms_stream_tx[i].channel = i;
		m_lms_stream_tx[i].fifoSize = 1024 * 1024;
		m_lms_stream_tx[i].throughputVsLatency = 0.3;
		m_lms_stream_tx[i].dataFmt = lms_stream_t::LMS_FMT_I16;

		if (LMS_SetupStream(m_lms_dev, &m_lms_stream_rx[i]) < 0)
			return false;

		if (LMS_SetupStream(m_lms_dev, &m_lms_stream_tx[i]) < 0)
			return false;
	}

	/* now start the streams in a second loop, as we can no longer call
	 * LMS_SetupStream() after LMS_StartStream() of the first stream */
	for (i = 0; i < chans; i++) {
		if (LMS_StartStream(&m_lms_stream_rx[i]) < 0)
			return false;

		if (LMS_StartStream(&m_lms_stream_tx[i]) < 0)
			return false;
	}

	flush_recv(10);

	started = true;
	return true;
}

bool LMSDevice::stop()
{
	unsigned int i;

	if (!started)
		return true;

	for (i=0; i<chans; i++) {
		LMS_StopStream(&m_lms_stream_tx[i]);
		LMS_StopStream(&m_lms_stream_rx[i]);
	}

	for (i=0; i<chans; i++) {
		LMS_DestroyStream(m_lms_dev, &m_lms_stream_tx[i]);
		LMS_DestroyStream(m_lms_dev, &m_lms_stream_rx[i]);
	}

	started = false;
	return true;
}

bool LMSDevice::do_clock_src_freq(enum ReferenceType ref, double freq)
{
	struct dev_desc dev_desc = dev_param_map.at(m_dev_type);
	size_t lms_clk_id;

	switch (ref) {
	case REF_EXTERNAL:
		lms_clk_id = LMS_CLOCK_EXTREF;
		break;
	case REF_INTERNAL:
		if (!dev_desc.clock_src_int_usable) {
			LOGC(DDEV, ERROR) << "Device type " << dev_desc.name_prefix
					  << " doesn't support internal reference clock";
			return false;
		}
		/* According to lms using LMS_CLOCK_EXTREF with a
		   frequency <= 0 is the correct way to set clock to
		   internal reference */
		lms_clk_id = LMS_CLOCK_EXTREF;
		freq = -1;
		break;
	default:
		LOGC(DDEV, ERROR) << "Invalid reference type " << get_value_string(clock_ref_names, ref);
		return false;
	}

	if (dev_desc.clock_src_switchable) {
		if (LMS_SetClockFreq(m_lms_dev, lms_clk_id, freq) < 0)
			return false;
	} else {
		LOGC(DDEV, INFO) << "Device type " << dev_desc.name_prefix
				 << " doesn't support switching clock source through SW";
	}

	return true;
}

/* do rx/tx calibration - depends on gain, freq and bw */
bool LMSDevice::do_calib(size_t chan)
{
	LOGCHAN(chan, DDEV, INFO) << "Calibrating";
	if (LMS_Calibrate(m_lms_dev, LMS_CH_RX, chan, LMS_CALIBRATE_BW_HZ, 0) < 0)
		return false;
	if (LMS_Calibrate(m_lms_dev, LMS_CH_TX, chan, LMS_CALIBRATE_BW_HZ, 0) < 0)
		return false;
	return true;
}

/* do rx/tx filter config - depends on bw only? */
bool LMSDevice::do_filters(size_t chan)
{
	lms_range_t range_lpfbw_rx, range_lpfbw_tx;
	float_type lpfbw_rx, lpfbw_tx;

	LOGCHAN(chan, DDEV, INFO) << "Setting filters";
	if (LMS_GetLPFBWRange(m_lms_dev, LMS_CH_RX, &range_lpfbw_rx))
		return false;
	print_range("LPFBWRange Rx", &range_lpfbw_rx);
	if (LMS_GetLPFBWRange(m_lms_dev, LMS_CH_RX, &range_lpfbw_tx))
		return false;
	print_range("LPFBWRange Tx", &range_lpfbw_tx);

	lpfbw_rx = OSMO_MIN(OSMO_MAX(1.4001e6, range_lpfbw_rx.min), range_lpfbw_rx.max);
	lpfbw_tx = OSMO_MIN(OSMO_MAX(5.2e6, range_lpfbw_tx.min), range_lpfbw_tx.max);

	LOGCHAN(chan, DDEV, INFO) << "LPFBW: Rx=" << lpfbw_rx << " Tx=" << lpfbw_tx;

	LOGCHAN(chan, DDEV, INFO) << "Setting LPFBW";
	if (LMS_SetLPFBW(m_lms_dev, LMS_CH_RX, chan, lpfbw_rx) < 0)
		return false;
	if (LMS_SetLPFBW(m_lms_dev, LMS_CH_TX, chan, lpfbw_tx) < 0)
		return false;
	return true;
}

double LMSDevice::maxRxGain()
{
	return 73.0;
}

double LMSDevice::minRxGain()
{
	return 0.0;
}

double LMSDevice::setRxGain(double dB, size_t chan)
{
	if (dB > maxRxGain())
		dB = maxRxGain();
	if (dB < minRxGain())
		dB = minRxGain();

	LOGCHAN(chan, DDEV, NOTICE) << "Setting RX gain to " << dB << " dB";

	if (LMS_SetGaindB(m_lms_dev, LMS_CH_RX, chan, dB) < 0)
		LOGCHAN(chan, DDEV, ERR) << "Error setting RX gain to " << dB << " dB";
	else
		rx_gains[chan] = dB;
	return rx_gains[chan];
}

double LMSDevice::rssiOffset(size_t chan)
{
	double rssiOffset;
	dev_band_desc desc;

	if (chan >= rx_gains.size()) {
		LOGC(DDEV, ALERT) << "Requested non-existent channel " << chan;
		return 0.0f;
	}

	get_dev_band_desc(desc);
	rssiOffset = rx_gains[chan] + desc.rxgain2rssioffset_rel;
	return rssiOffset;
}

double LMSDevice::setPowerAttenuation(int atten, size_t chan)
{
	double tx_power, dB;
	dev_band_desc desc;

	if (chan >= tx_gains.size()) {
		LOGC(DDEV, ALERT) << "Requested non-existent channel " << chan;
		return 0.0f;
	}

	get_dev_band_desc(desc);
	tx_power = desc.nom_out_tx_power - atten;
	dB = TxPower2TxGain(desc, tx_power);

	LOGCHAN(chan, DDEV, NOTICE) << "Setting TX gain to " << dB << " dB (~" << tx_power << " dBm)";

	if (LMS_SetGaindB(m_lms_dev, LMS_CH_TX, chan, dB) < 0)
		LOGCHAN(chan, DDEV, ERR) << "Error setting TX gain to " << dB << " dB (~" << tx_power << " dBm)";
	else
		tx_gains[chan] = dB;
	return desc.nom_out_tx_power - TxGain2TxPower(desc, tx_gains[chan]);
}

double LMSDevice::getPowerAttenuation(size_t chan) {
	dev_band_desc desc;
	if (chan >= tx_gains.size()) {
		LOGC(DDEV, ALERT) << "Requested non-existent channel " << chan;
		return 0.0f;
	}

	get_dev_band_desc(desc);
	return desc.nom_out_tx_power - TxGain2TxPower(desc, tx_gains[chan]);
}

int LMSDevice::getNominalTxPower(size_t chan)
{
	dev_band_desc desc;
	get_dev_band_desc(desc);

	return desc.nom_out_tx_power;
}

void LMSDevice::log_ant_list(bool dir_tx, size_t chan, std::ostringstream& os)
{
	lms_name_t name_list[MAX_ANTENNA_LIST_SIZE]; /* large enough list for antenna names. */
	int num_names;
	int i;

	num_names = LMS_GetAntennaList(m_lms_dev, dir_tx, chan, name_list);
	for (i = 0; i < num_names; i++) {
		if (i)
			os << ", ";
		os << "'" << name_list[i] << "'";
	}
}

int LMSDevice::get_ant_idx(const std::string & name, bool dir_tx, size_t chan)
{
	lms_name_t name_list[MAX_ANTENNA_LIST_SIZE]; /* large enough list for antenna names. */
	const char* c_name = name.c_str();
	int num_names;
	int i;

	num_names = LMS_GetAntennaList(m_lms_dev, dir_tx, chan, name_list);
	for (i = 0; i < num_names; i++) {
		if (!strcmp(c_name, name_list[i]))
			return i;
	}
	return -1;
}

bool LMSDevice::flush_recv(size_t num_pkts)
{
	#define CHUNK 625
	int len = CHUNK * tx_sps;
	short *buffer = (short*) alloca(sizeof(short) * len * 2);
	int rc;
	lms_stream_meta_t rx_metadata = {};
	rx_metadata.flushPartialPacket = false;
	rx_metadata.waitForTimestamp = false;

	ts_initial = 0;

	while (!ts_initial || (num_pkts-- > 0)) {
		rc = LMS_RecvStream(&m_lms_stream_rx[0], &buffer[0], len, &rx_metadata, 100);
		LOGC(DDEV, DEBUG) << "Flush: Recv buffer of len " << rc << " at " << std::hex << rx_metadata.timestamp;
		if (rc != len) {
			LOGC(DDEV, ERROR) << "Flush: Device receive timed out";
			return false;
		}

		ts_initial = rx_metadata.timestamp + len;
	}

	LOGC(DDEV, INFO) << "Initial timestamp " << ts_initial << std::endl;
	return true;
}

bool LMSDevice::setRxAntenna(const std::string & ant, size_t chan)
{
	int idx;

	if (chan >= rx_paths.size()) {
		LOGC(DDEV, ERROR) << "Requested non-existent channel " << chan;
		return false;
	}

	idx = get_ant_idx(ant, LMS_CH_RX, chan);
	if (idx < 0) {
		std::ostringstream os;
		LOGCHAN(chan, DDEV, ERROR) << "Invalid Rx Antenna: " << ant;
		log_ant_list(LMS_CH_RX, chan, os);
		LOGCHAN(chan, DDEV, NOTICE) << "Available Rx Antennas: " << os;
		return false;
	}

	if (LMS_SetAntenna(m_lms_dev, LMS_CH_RX, chan, idx) < 0) {
		LOGCHAN(chan, DDEV, ERROR) << "Unable to set Rx Antenna";
	}

	return true;
}

std::string LMSDevice::getRxAntenna(size_t chan)
{
	lms_name_t name_list[MAX_ANTENNA_LIST_SIZE]; /* large enough list for antenna names. */
	int idx;

	if (chan >= rx_paths.size()) {
		LOGC(DDEV, ERROR) << "Requested non-existent channel " << chan;
		return "";
	}

	idx = LMS_GetAntenna(m_lms_dev, LMS_CH_RX, chan);
	if (idx < 0) {
		LOGCHAN(chan, DDEV, ERROR) << "Error getting Rx Antenna";
		return "";
	}

	if (LMS_GetAntennaList(m_lms_dev, LMS_CH_RX, chan, name_list) < idx) {
		LOGCHAN(chan, DDEV, ERROR) << "Error getting Rx Antenna List";
		return "";
	}

	return name_list[idx];
}

bool LMSDevice::setTxAntenna(const std::string & ant, size_t chan)
{
	int idx;

	if (chan >= tx_paths.size()) {
		LOGC(DDEV, ERROR) << "Requested non-existent channel " << chan;
		return false;
	}

	idx = get_ant_idx(ant, LMS_CH_TX, chan);
	if (idx < 0) {
		std::ostringstream os;
		LOGCHAN(chan, DDEV, ERROR) << "Invalid Tx Antenna: " << ant;
		log_ant_list(LMS_CH_TX, chan, os);
		LOGCHAN(chan, DDEV, NOTICE) << "Available Tx Antennas: " << os;
		return false;
	}

	if (LMS_SetAntenna(m_lms_dev, LMS_CH_TX, chan, idx) < 0) {
		LOGCHAN(chan, DDEV, ERROR) << "Unable to set Rx Antenna";
	}

	return true;
}

std::string LMSDevice::getTxAntenna(size_t chan)
{
	lms_name_t name_list[MAX_ANTENNA_LIST_SIZE]; /* large enough list for antenna names. */
	int idx;

	if (chan >= tx_paths.size()) {
		LOGC(DDEV, ERROR) << "Requested non-existent channel " << chan;
		return "";
	}

	idx = LMS_GetAntenna(m_lms_dev, LMS_CH_TX, chan);
	if (idx < 0) {
		LOGCHAN(chan, DDEV, ERROR) << "Error getting Tx Antenna";
		return "";
	}

	if (LMS_GetAntennaList(m_lms_dev, LMS_CH_TX, chan, name_list) < idx) {
		LOGCHAN(chan, DDEV, ERROR) << "Error getting Tx Antenna List";
		return "";
	}

	return name_list[idx];
}

bool LMSDevice::requiresRadioAlign()
{
	return false;
}

GSM::Time LMSDevice::minLatency() {
	/* UNUSED on limesdr (only used on usrp1/2) */
	return GSM::Time(0,0);
}
/*!
 * Issue tracking description of several events: https://github.com/myriadrf/LimeSuite/issues/265
 */
void LMSDevice::update_stream_stats_rx(size_t chan, bool *overrun)
{
	lms_stream_status_t status;
	bool changed = false;

	if (LMS_GetStreamStatus(&m_lms_stream_rx[chan], &status) != 0) {
		LOGCHAN(chan, DDEV, ERROR) << "Rx LMS_GetStreamStatus failed";
		return;
	}

	/* FIFO overrun is counted when Rx FIFO is full but new data comes from
	   the board and oldest samples in FIFO are overwritte. Value count
	   since the last call to LMS_GetStreamStatus(stream). */
	if (status.overrun) {
		changed = true;
		*overrun = true;
		LOGCHAN(chan, DDEV, ERROR) << "Rx Overrun! ("
					   << m_ctr[chan].rx_overruns << " -> "
					   << status.overrun << ")";
	}
	m_ctr[chan].rx_overruns += status.overrun;

	/* Dropped packets in Rx are counted when gaps in Rx timestamps are
	   detected (likely because buffer overflow in hardware). Value count
	   since the last call to LMS_GetStreamStatus(stream). */
	if (status.droppedPackets) {
		changed = true;
		LOGCHAN(chan, DDEV, ERROR) << "Rx Dropped packets by HW! ("
					   << m_ctr[chan].rx_dropped_samples << " -> "
					   << m_ctr[chan].rx_dropped_samples +
					      status.droppedPackets
					   << ")";
		m_ctr[chan].rx_dropped_events++;
	}
	m_ctr[chan].rx_dropped_samples += status.droppedPackets;

	if (changed)
		osmo_signal_dispatch(SS_DEVICE, S_DEVICE_COUNTER_CHANGE, &m_ctr[chan]);

}

// NOTE: Assumes sequential reads
int LMSDevice::readSamples(std::vector < short *>&bufs, int len, bool * overrun,
			   TIMESTAMP timestamp, bool * underrun)
{
	int rc, num_smpls, expect_smpls;
	ssize_t avail_smpls;
	TIMESTAMP expect_timestamp;
	unsigned int i;
	lms_stream_meta_t rx_metadata = {};
	rx_metadata.flushPartialPacket = false;
	rx_metadata.waitForTimestamp = false;
	rx_metadata.timestamp = 0;

	if (bufs.size() != chans) {
		LOGC(DDEV, ERROR) << "Invalid channel combination " << bufs.size();
		return -1;
	}

	*overrun = false;
	*underrun = false;

	/* Check that timestamp is valid */
	rc = rx_buffers[0]->avail_smpls(timestamp);
	if (rc < 0) {
		LOGC(DDEV, ERROR) << rx_buffers[0]->str_code(rc);
		LOGC(DDEV, ERROR) << rx_buffers[0]->str_status(timestamp);
		return 0;
	}

	for (i = 0; i<chans; i++) {
		/* Receive samples from HW until we have enough */
		while ((avail_smpls = rx_buffers[i]->avail_smpls(timestamp)) < len) {
			thread_enable_cancel(false);
			num_smpls = LMS_RecvStream(&m_lms_stream_rx[i], bufs[i], len - avail_smpls, &rx_metadata, 100);
			update_stream_stats_rx(i, overrun);
			thread_enable_cancel(true);
			if (num_smpls <= 0) {
				LOGCHAN(i, DDEV, ERROR) << "Device receive timed out (" << rc << " vs exp " << len << ").";
				return -1;
			}

			LOGCHAN(i, DDEV, DEBUG) "Received timestamp = " << (TIMESTAMP)rx_metadata.timestamp << " (" << num_smpls << ")";

			expect_smpls = len - avail_smpls;
			if (expect_smpls != num_smpls)
				LOGCHAN(i, DDEV, NOTICE) << "Unexpected recv buffer len: expect "
							 << expect_smpls << " got " << num_smpls
							 << ", diff=" << expect_smpls - num_smpls;

			expect_timestamp = timestamp + avail_smpls;
			if (expect_timestamp != (TIMESTAMP)rx_metadata.timestamp)
				LOGCHAN(i, DDEV, ERROR) << "Unexpected recv buffer timestamp: expect "
							<< expect_timestamp << " got " << (TIMESTAMP)rx_metadata.timestamp
							<< ", diff=" << rx_metadata.timestamp - expect_timestamp;

			rc = rx_buffers[i]->write(bufs[i], num_smpls, (TIMESTAMP)rx_metadata.timestamp);
			if (rc < 0) {
				LOGCHAN(i, DDEV, ERROR) << rx_buffers[i]->str_code(rc);
				LOGCHAN(i, DDEV, ERROR) << rx_buffers[i]->str_status(timestamp);
				if (rc != smpl_buf::ERROR_OVERFLOW)
					return 0;
			}
		}
	}

	/* We have enough samples */
	for (size_t i = 0; i < rx_buffers.size(); i++) {
		rc = rx_buffers[i]->read(bufs[i], len, timestamp);
		if ((rc < 0) || (rc != len)) {
			LOGCHAN(i, DDEV, ERROR) << rx_buffers[i]->str_code(rc) << ". "
						<< rx_buffers[i]->str_status(timestamp)
						<< ", (len=" << len << ")";
			return 0;
		}
	}

	return len;
}

void LMSDevice::update_stream_stats_tx(size_t chan, bool *underrun)
{
	lms_stream_status_t status;
	bool changed = false;

	if (LMS_GetStreamStatus(&m_lms_stream_tx[chan], &status) != 0) {
		LOGCHAN(chan, DDEV, ERROR) << "Tx LMS_GetStreamStatus failed";
		return;
	}

	/* FIFO underrun is counted when Tx is running but FIFO is empty for
	   >100 ms (500ms in older versions). Value count since the last call to
	   LMS_GetStreamStatus(stream). */
	if (status.underrun) {
		changed = true;
		*underrun = true;
		LOGCHAN(chan, DDEV, ERROR) << "Tx Underrun! ("
					   << m_ctr[chan].tx_underruns << " -> "
					   << status.underrun << ")";
	}
	m_ctr[chan].tx_underruns += status.underrun;

	/* Dropped packets in Tx are counted only when timestamps are enabled
	   and SDR drops packet because of late timestamp. Value count since the
	   last call to LMS_GetStreamStatus(stream). */
	if (status.droppedPackets) {
		changed = true;
		LOGCHAN(chan, DDEV, ERROR) << "Tx Dropped packets by HW! ("
					   << m_ctr[chan].tx_dropped_samples << " -> "
					   << m_ctr[chan].tx_dropped_samples +
					      status.droppedPackets
					   << ")";
		m_ctr[chan].tx_dropped_events++;
	}
	m_ctr[chan].tx_dropped_samples += status.droppedPackets;

	if (changed)
		osmo_signal_dispatch(SS_DEVICE, S_DEVICE_COUNTER_CHANGE, &m_ctr[chan]);

}

int LMSDevice::writeSamples(std::vector < short *>&bufs, int len,
			    bool * underrun, unsigned long long timestamp)
{
	int rc = 0;
	unsigned int i;
	lms_stream_meta_t tx_metadata = {};
	tx_metadata.flushPartialPacket = false;
	tx_metadata.waitForTimestamp = true;
	tx_metadata.timestamp = timestamp - ts_offset;	/* Shift Tx time by offset */

	if (bufs.size() != chans) {
		LOGC(DDEV, ERROR) << "Invalid channel combination " << bufs.size();
		return -1;
	}

	*underrun = false;

	for (i = 0; i<chans; i++) {
		LOGCHAN(i, DDEV, DEBUG) << "send buffer of len " << len << " timestamp " << std::hex << tx_metadata.timestamp;
		thread_enable_cancel(false);
		rc = LMS_SendStream(&m_lms_stream_tx[i], bufs[i], len, &tx_metadata, 100);
		update_stream_stats_tx(i, underrun);
		thread_enable_cancel(true);
		if (rc != len) {
			LOGCHAN(i, DDEV, ERROR) << "LMS: Device Tx timed out (" << rc << " vs exp " << len << ").";
			return -1;
		}
	}

	return rc;
}

bool LMSDevice::updateAlignment(TIMESTAMP timestamp)
{
	return true;
}

bool LMSDevice::setTxFreq(double wFreq, size_t chan)
{
	uint16_t req_arfcn;
	enum gsm_band req_band;

	if (chan >= chans) {
		LOGC(DDEV, ALERT) << "Requested non-existent channel " << chan;
		return false;
	}

	LOGCHAN(chan, DDEV, NOTICE) << "Setting Tx Freq to " << wFreq << " Hz";

	req_arfcn = gsm_freq102arfcn(wFreq / 1000 / 100 , 0);
	if (req_arfcn == 0xffff) {
		LOGCHAN(chan, DDEV, ALERT) << "Unknown ARFCN for Tx Frequency " << wFreq / 1000 << " kHz";
		return false;
	}
	if (gsm_arfcn2band_rc(req_arfcn, &req_band) < 0) {
		LOGCHAN(chan, DDEV, ALERT) << "Unknown GSM band for Tx Frequency " << wFreq
					   << " Hz (ARFCN " << req_arfcn << " )";
		return false;
	}

	if (band != 0 && req_band != band) {
		LOGCHAN(chan, DDEV, ALERT) << "Requesting Tx Frequency " << wFreq
					   << " Hz different from previous band " << gsm_band_name(band);
		return false;
	}

	if (!set_band(req_band))
		return false;

	if (LMS_SetLOFrequency(m_lms_dev, LMS_CH_TX, chan, wFreq) < 0) {
		LOGCHAN(chan, DDEV, ERROR) << "Error setting Tx Freq to " << wFreq << " Hz";
		return false;
	}

	return true;

}

bool LMSDevice::setRxFreq(double wFreq, size_t chan)
{
	LOGCHAN(chan, DDEV, NOTICE) << "Setting Rx Freq to " << wFreq << " Hz";

	if (LMS_SetLOFrequency(m_lms_dev, LMS_CH_RX, chan, wFreq) < 0) {
		LOGCHAN(chan, DDEV, ERROR) << "Error setting Rx Freq to " << wFreq << " Hz";
		return false;
	}

	return true;
}

RadioDevice *RadioDevice::make(size_t tx_sps, size_t rx_sps,
			       InterfaceType iface, size_t chans, double lo_offset,
			       const std::vector < std::string > &tx_paths,
			       const std::vector < std::string > &rx_paths)
{
	if (tx_sps != rx_sps) {
		LOGC(DDEV, ERROR) << "LMS Requires tx_sps == rx_sps";
		return NULL;
	}
	if (lo_offset != 0.0) {
		LOGC(DDEV, ERROR) << "LMS doesn't support lo_offset";
		return NULL;
	}
	return new LMSDevice(tx_sps, rx_sps, iface, chans, lo_offset, tx_paths, rx_paths);
}
