import logging
import os
import re
import subprocess
import sys
import threading
import time
import traceback
from argparse import ArgumentParser
from datetime import datetime, timedelta
from enum import Enum
from telnetlib import Telnet
from typing import Optional, List, Union
import pprint
from multiprocessing import Process
import pwd

import smpplib.client
import smpplib.consts
import smpplib.gsm


class Subscriber:

    def __init__(self, imsi, msisdn, imei, last_seen, cell, calls_status, sms_status):
        self.imsi = imsi
        self.msisdn = msisdn
        self.imei = imei
        self.last_seen = last_seen
        self.cell = cell
        self.short_cell = "/".join(cell.split("/")[-2:])
        self.calls_status = calls_status
        self.sms_status = sms_status

    def __repr__(self):
        return f"imsi={self.imsi}, msisdn={self.msisdn}, imei={self.imei}, cell={self.cell}, calls={self.calls_status}, sms={self.sms_status}"

    def __str__(self):
        return self.__repr__()

    @property
    def last_seen_int(self):
        return int(self.last_seen) if self.last_seen.isnumeric() else 0


########################################################################################################################
#         For process call logs                                                                                        #
########################################################################################################################
class CallStatus(Enum):
    NEW = "Будет совершен звонок"
    NOT_AVAILABLE = "Абонент недоступен"
    AVAILABLE = "Абонент доступен"
    INIT = "Инициализация звонка"
    RINGING = "Сигнал"
    ACTIVE = "Идет звонок"
    REJECT_BY_USER = "Звонок отклонен"
    UP = "Абонент ответил"
    HANGUP = "Звонок прекращен"
    HANGUP_BY_USER = "Звонок прекращен абонентом"
    HANGUP_BY_BTS = "Звонок прекращен БТС"
    BREAK_BY_BTS = "Инициализация прервана БТС"
    STOP_BY_BTS = "Звонок остановлен БТС во время сигнала"
    UNKNOWN = "Неизвестный переход состояний"

    def is_ended(self):
        return self in [self.NOT_AVAILABLE, self.REJECT_BY_USER, self.HANGUP_BY_USER, self.HANGUP_BY_BTS,
                        self.BREAK_BY_BTS, self.STOP_BY_BTS]


class CallState(Enum):
    NULL = "NULL"
    CALL_PRESENT = "CALL_PRESENT"
    MO_TERM_CALL_CONF = "MO_TERM_CALL_CONF"
    CALL_RECEIVED = "CALL_RECEIVED"
    CONNECT_REQUEST = "CONNECT_REQUEST"
    ACTIVE = "ACTIVE"
    DISCONNECT_IND = "DISCONNECT_IND"
    RELEASE_REQ = "RELEASE_REQ"
    BROKEN_BY_BTS = "BROKEN_BY_BTS"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    NEW = "NEW"


class CallStateEvent:

    def __init__(self, state: CallState, prev_state: CallState, event_time: str):
        self._state = state
        self._prev_state = prev_state
        self._event_time: str = event_time

    def status(self):
        return self._state

    def status_time(self):
        return self._event_time

    def prev_status(self):
        return self._prev_state

    def __repr__(self):
        return f"{self._event_time}: {self._prev_state.name} -> {self._state.name}"


class Call:
    _statuses = {
        (CallState.NEW, CallState.NULL): CallStatus.NEW,
        (CallState.NULL, CallState.CALL_PRESENT): CallStatus.AVAILABLE,
        (CallState.NULL, CallState.BROKEN_BY_BTS): CallStatus.BREAK_BY_BTS,
        (CallState.NULL, CallState.NOT_AVAILABLE): CallStatus.NOT_AVAILABLE,
        (CallState.CALL_PRESENT, CallState.RELEASE_REQ): CallStatus.BREAK_BY_BTS,
        (CallState.CALL_PRESENT, CallState.NULL): CallStatus.BREAK_BY_BTS,
        (CallState.CALL_PRESENT, CallState.MO_TERM_CALL_CONF): CallStatus.INIT,
        (CallState.RELEASE_REQ, CallState.NULL): None,
        (CallState.MO_TERM_CALL_CONF, CallState.RELEASE_REQ): CallStatus.BREAK_BY_BTS,
        (CallState.MO_TERM_CALL_CONF, CallState.NULL): CallStatus.BREAK_BY_BTS,
        (CallState.MO_TERM_CALL_CONF, CallState.CALL_RECEIVED): CallStatus.RINGING,
        (CallState.CALL_RECEIVED, CallState.DISCONNECT_IND): CallStatus.REJECT_BY_USER,
        (CallState.DISCONNECT_IND, CallState.RELEASE_REQ): CallStatus.HANGUP_BY_USER,
        (CallState.CALL_RECEIVED, CallState.CONNECT_REQUEST): CallStatus.UP,
        (CallState.CONNECT_REQUEST, CallState.ACTIVE): CallStatus.ACTIVE,
        (CallState.ACTIVE, CallState.DISCONNECT_IND): CallStatus.HANGUP,
        (CallState.DISCONNECT_IND, CallState.NULL): CallStatus.HANGUP_BY_BTS,
        (CallState.CALL_RECEIVED, CallState.RELEASE_REQ): CallStatus.STOP_BY_BTS,
        (CallState.CALL_RECEIVED, CallState.NULL): CallStatus.STOP_BY_BTS,

    }

    __LOG_NAME = os.path.dirname(os.path.abspath(__file__)) + "/calls_error.log"

    def __init__(self, imsi: str, callref: str, tid: str):
        self.imsi = imsi
        self.callref = callref
        self.tid = tid
        self.events = []
        self.statuses = []
        self.status: Optional[CallStatus] = None

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return f"{self.status.value}/{self.get_last_state()}({self.get_last_event_time()})"

    def _save_error(self, error: str):
        with open(self.__LOG_NAME, "a+") as f:
            f.write(error)
            f.write("\n")

    def add_event(self, event: CallStateEvent, tid):
        self.events.append(event)
        self.tid = tid
        if not self.status or not self.status.is_ended():
            if (event.prev_status(), event.status()) in self._statuses:
                new_status = self._statuses[(event.prev_status(), event.status())]
            else:
                self._save_error(f"Unknown event: {event.prev_status().name} -> {event.status().name}")
                new_status = CallStatus.UNKNOWN
            self.status = new_status or self.status
            self.statuses.append(self.status)

    def is_ended(self):
        return self.get_last_state() in [CallState.NOT_AVAILABLE, CallState.BROKEN_BY_BTS] or \
               (self.get_last_state() == CallState.NULL and len(self.events) > 1)

    def get_last_state(self):
        return self.events[-1].status()

    def get_last_event_time(self):
        return self.events[-1].status_time()

    def get_info(self):
        return {
            "ended": self.is_ended(),
            "imsi": self.imsi,
            "last_time": self.get_last_event_time(),
            "status": self.status.value
        }


class EventLine:
    _templates = [
        re.compile("trans\(CC.*IMSI-([0-9]+):")  # IMSI
        , re.compile("callref-0x([0-9a-f]+) ")  # callref
        , re.compile(" tid-([0-9]+)[,)]")  # tid
        , re.compile("^(.*) bts")  # time
        , re.compile(" new state (.+) -> .+$")  # prev state
        , re.compile(" new state .+ -> (.+)$")  # new state
        , re.compile("tid-255.* (Paging expired)$")  # expired
        , re.compile(" (New transaction)$")  # new_transaction
        , re.compile("^.* bts.*(Started Osmocom Mobile Switching Center)")  # service started
        , re.compile("tid-255.* tx (MNCC_REL_CNF)$")
    ]

    _exclude = re.compile("callref-0x(4|8)[0-9a-f]{7,7}")

    def __init__(self):
        self.imsi = ""
        self.callref = ""
        self.tid = ""
        self.event_time = ""
        self.event: Optional[CallStateEvent] = None
        self.is_started_event = False

    def __repr__(self):
        prefix = f"{self.imsi}/{self.callref}/{self.tid}"
        if self.is_started_event:
            return f"{self.event_time}: Osmocom started"
        else:
            return f"{prefix}: {self.event.prev_status().name} -> {self.event.status().name}"

    @classmethod
    def create(cls, line):
        if cls._exclude.search(line):
            return None

        results = []
        for template in cls._templates:
            match = template.search(line)
            results.append(match.group(1) if match else "")

        event = EventLine()

        imsi, callref, tid, event_time, from_state, to_state, expired, new_transaction, started, bts_break = results
        event.imsi = imsi
        event.callref = callref
        event.tid = tid
        event.event_time = event_time
        if new_transaction:
            event.event = CallStateEvent(CallState.NULL, CallState.NEW, event_time)
        elif started:
            event.is_started_event = True
        elif bts_break:
            event.event = CallStateEvent(CallState.BROKEN_BY_BTS, CallState.NULL, event_time)
        elif expired:
            event.event = CallStateEvent(CallState.NOT_AVAILABLE, CallState.NULL, event_time)
        elif from_state and to_state:
            event.event = CallStateEvent(CallState(to_state), CallState(from_state), event_time)
        else:
            raise Exception("Unknown event")

        return event


class CallTimestamp:
    __FILE_NAME = os.path.dirname(os.path.abspath(__file__)) + "/call_timestamp"
    __WORK_STATUS = "work"
    __STOP_STATUS = "stop"

    @classmethod
    def start_calls(cls):
        try:
            with open(cls.__FILE_NAME, "r") as f:
                lines = f.readlines()
                if len(lines) == 2 and lines[0].strip() == cls.__WORK_STATUS:
                    return

        except IOError:
            pass

        with open(cls.__FILE_NAME, "w") as f:
            f.writelines([cls.__WORK_STATUS, "\n", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])

    @classmethod
    def stop_calls(cls):
        since = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        until = since
        try:
            with open(cls.__FILE_NAME, "r") as f:
                lines = f.readlines()
                if len(lines) == 2:
                    since = lines[1].strip()

        except IOError:
            pass

        with open(cls.__FILE_NAME, "w") as f:
            f.writelines([cls.__STOP_STATUS, "\n", since, "\n", until])

    @classmethod
    def get_period(cls):
        since = None
        until = None
        try:
            with open(cls.__FILE_NAME, "r") as f:
                lines = f.readlines()
                if len(lines) >= 2:
                    since = lines[1].strip()
                if lines[0].strip() == cls.__STOP_STATUS and len(lines) == 3:
                    until = lines[2].strip()
                    until = datetime.strptime(until, "%Y-%m-%d %H:%M:%S") + timedelta(seconds=30)
                    until = until.strftime("%Y-%m-%d %H:%M:%S")
        except IOError:
            pass
        return since, until


class SmsTimestamp:
    __FILE_NAME = os.path.dirname(os.path.abspath(__file__)) + "/sms_timestamp"
    __sms_period_time = 30

    @classmethod
    def update(cls):
        with open(cls.__FILE_NAME, "w") as f:
            f.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    @classmethod
    def get_period(cls):
        since = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(cls.__FILE_NAME, "r") as f:
                lines = f.readlines()
                if len(lines) == 1:
                    since = lines[0].strip()
        except IOError:
            pass

        until = datetime.strptime(since, "%Y-%m-%d %H:%M:%S") + timedelta(seconds=cls.__sms_period_time)
        until = until.strftime("%Y-%m-%d %H:%M:%S")
        return since, until


########################################################################################################################

class CallType(Enum):
    MP3 = 1,
    GSM = 2,
    SILENT = 3


class Sdr:

    def __init__(self, msc_host: str = "localhost", msc_port_vty: int = 4254,
                 smpp_host: str = "localhost", smpp_port: int = 2775, smpp_id: str = "OSMO-SMPP",
                 smpp_password: str = "1234", debug_output: bool = False, bsc_host: str = "localhost",
                 bsc_port_vty: int = 4242):
        self._msc_host = msc_host
        self._msc_port_vty = msc_port_vty
        self._smpp_host = smpp_host
        self._smpp_port = smpp_port
        self._smpp_id = smpp_id
        self._smpp_password = smpp_password
        self._logger = logging.getLogger("SDR")
        self._bsc_host = bsc_host
        self._bsc_port_vty = bsc_port_vty

        if debug_output:
            self._logger.setLevel(logging.DEBUG)
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)

    def _check_msisdn(self, msisdn):
        start_cmd = f"subscriber msisdn {msisdn} silent-call start any signalling\r\n".encode()
        stop_cmd = f"subscriber msisdn {msisdn} silent-call stop\r\n".encode()
        expired_cmd = f"enable\r\nsubscriber msisdn {msisdn} expire\r\n".encode()
        with Telnet(self._msc_host, self._msc_port_vty) as tn:
            tn.write(start_cmd)
            try:
                result = tn.expect([b"Silent call success", b"Silent call failed", b"Silent call ended",
                                    b"No subscriber found for", b"Subscriber not attached",
                                    b"Cannot start silent call"], 11)

                if result[0] == 0:  # success
                    tn.write(stop_cmd)
                    tn.expect([b"% Silent call stopped"], 2)
                    return "ok"
                elif result[0] in (-1, 1):  # timeout
                    tn.write(expired_cmd)
                    return "expired"

            except EOFError as e:
                print(f"SDRError: {traceback.format_exc()}")
            return "error"

    def _silent_call(self, msisdn, result_list, channel="tch/h", silent_call_type="speech-amr"):

        start_cmd = f"subscriber msisdn {msisdn} silent-call start {channel} {silent_call_type}\r\n".encode()
        stop_cmd = f"subscriber msisdn {msisdn} silent-call stop\r\n".encode()
        with Telnet(self._msc_host, self._msc_port_vty) as tn:
            tn.write(start_cmd)
            try:
                result = tn.expect([b"Silent call success", b"Silent call failed", b"Silent call ended",
                                    b"No subscriber found for", b"Subscriber not attached",
                                    b"Cannot start silent call"], 11)

                if result[0] == 0:  # success
                    time.sleep(3)
                    tn.write(stop_cmd)
                    tn.expect([b"% Silent call stopped"], 2)
                    result_list.append(("ok", msisdn))
                    return "ok", msisdn
                elif result[0] in (-1, 1):  # timeout
                    tn.write(stop_cmd)
                    result_list.append(("expired", msisdn))
                    return "expired", msisdn

            except EOFError as e:
                print(f"SDRError: {traceback.format_exc()}")

            result_list.append(("error", msisdn))
            tn.write(stop_cmd)
            return "error", msisdn

    def _get_subscribers(self):
        start_cmd = f"subscriber list\r\n".encode()
        subscribers = []
        with Telnet(self._msc_host, self._msc_port_vty) as tn:
            tn.write(start_cmd)
            try:
                result = tn.expect([b"subscriber list end"], 11)

                analyze = False
                if result[0] == 0:  # success
                    for line in result[2].split(b"\r\n"):
                        if line == b"subscriber list begin":
                            analyze = True
                        elif line == b"subscriber list end":
                            break
                        elif analyze:
                            elements = line.decode("ascii").split(",")
                            subscribers.append(
                                Subscriber(elements[0], elements[1], elements[2], elements[3], elements[4], [], []))

            except EOFError as e:
                print(f"SDRError: {traceback.format_exc()}")

            return subscribers

    def _clear_expired(self):
        threads = [threading.Thread(target=self._check_msisdn, args=(subscriber.msisdn,))
                   for subscriber in self._get_subscribers()]
        list(map(lambda x: x.start(), threads))

        for index, thread in enumerate(threads):
            self._logger.debug("Main    : before joining thread %d.", index)
            thread.join()
            self._logger.debug("Main    : thread %d done", index)

    def silent_call(self, channel="tch/h", silent_call_type="speech-amr"):
        subscribers = self._get_subscribers()

        attempts = 3
        ok_count = 0
        all_count = len(subscribers)

        while attempts and subscribers:
            attempts -= 1
            results = []
            threads = [threading.Thread(target=self._silent_call,
                                        args=(subscriber.msisdn, results, channel, silent_call_type)) for subscriber
                       in subscribers]
            list(map(lambda x: x.start(), threads))

            for index, thread in enumerate(threads):
                thread.join()

            ok_count += len([1 for result in results if result[0] == "ok"])
            self._logger.debug(f"Silent call ok count {ok_count}/{all_count}")
            repeat_msisdn = [result[1] for result in results if result[0] != "ok"]
            subscribers = [subscriber for subscriber in subscribers if subscriber.msisdn in repeat_msisdn]

        self._logger.debug(f"ok:{ok_count}, fail:{len(subscribers)}")
        return ok_count

    def get_subscribers(self, check_before: bool = False, with_status: bool = False):
        if check_before:
            self._clear_expired()
        subscribers = self._get_subscribers()

        if with_status:
            call_records = self.calls_status()
            sms_records = self.sms_statuses()

            for subscriber in subscribers:
                subscriber.calls_status = call_records[subscriber.imsi] if subscriber.imsi in call_records else []
                subscriber.sms_status = sms_records[subscriber.imsi] if subscriber.imsi in sms_records else []

        return subscribers

    def call(self, call_type: CallType, call_to: Union[str, List[str]], call_from: str = "00000",
             voice_file: Optional[str] = None,
             set_call_timestamp: bool = False):

        if set_call_timestamp:
            CallTimestamp.start_calls()

        self._logger.debug(f"{call_type}, {call_to}, {call_from}, {voice_file}")
        asterisk_sounds_path = "/usr/share/asterisk/sounds/en_US_f_Allison/"

        if call_type in (CallType.GSM, CallType.MP3) and voice_file is None:
            raise Exception("Need voice file")

        if call_type == CallType.GSM:
            if os.path.isfile(voice_file):
                os.system(f"cp -f {voice_file} {asterisk_sounds_path}")
                voice_file = os.path.split(voice_file)[1].split(".")[0]
            else:
                if not os.path.isfile(f"{asterisk_sounds_path}{voice_file}.gsm"):
                    raise Exception(f"Not found file: {voice_file}")

        if call_type == CallType.MP3 and not os.path.isfile(voice_file):
            raise Exception(f"Not found file: {voice_file}")

        extension = "gsm" if call_type == CallType.GSM else (
            "mp3" if call_type == CallType.MP3 else "silent")
        data = "" if call_type == CallType.SILENT else f"\nSetvar: voice_file={voice_file}"

        call_to = call_to if isinstance(call_to, list) else [call_to]

        def write_as_asterisk(msisdns):
            r = pwd.getpwnam("asterisk")
            os.setgid(r.pw_gid)
            os.setuid(r.pw_uid)

            umask = os.umask(0)

            idx = 0
            for callee in msisdns:
                call_data = f"Channel: SIP/GSM/{callee}\n" \
                            f"MaxRetries: 500\n" \
                            f"RetryTime: 1\n" \
                            f"WaitTime: 30\n" \
                            f"CallerID: {call_from}\n" \
                            f"Context: calls\n" \
                            f"Extension: {extension}\n" \
                            f"Priority: 1\n" \
                            + data
                idx += 1
                call_file = "/var/spool/asterisk/outgoing/{:06d}.call".format(idx)

                with open(call_file, "w") as f:
                    f.write(call_data)
            os.umask(umask)

        p = Process(target=write_as_asterisk, args=(call_to,))
        p.start()
        p.join()

    def _get_filtered_subscribers(self, exclude=False, include=False, exclude_2sim=True):
        exclude_list = []
        current_path = os.path.dirname(os.path.abspath(__file__))
        if exclude:
            with open(current_path + "/exclude_list") as f:
                exclude_list = [line.strip()[:14] for line in f.readlines()]
        elif include:
            with open(current_path + "/include_list") as f:
                include_list = [line.strip()[:14] for line in f.readlines()]

        all_subscibers = sorted(self.get_subscribers(),
                                key=lambda x: x.last_seen_int)
        all_subscibers = [subscriber for subscriber in all_subscibers if
                          (exclude and subscriber.imei not in exclude_list) or \
                          (include and subscriber.imei in include_list) or \
                          (not include and not exclude)]

        exclude_2sim_list = []
        if exclude_2sim:
            for idx, subscriber_1 in enumerate(all_subscibers):
                for subscriber_2 in all_subscibers[idx + 1:]:
                    diff_cnt = sum([1 if subscriber_1.imei[ch_idx] != subscriber_2.imei[ch_idx] else 0 for ch_idx
                                    in range(len(subscriber_1.imei))])
                    if diff_cnt <= 2:
                        exclude_2sim_list.append(subscriber_1 if subscriber_1.last_seen_int > subscriber_2.last_seen_int
                                                 else subscriber_2)
                        break

        return [subscriber for subscriber in all_subscibers if subscriber not in exclude_2sim_list]

    def call_to_all(self, call_type: CallType = CallType.GSM, voice_file: str = "gubin", call_from: str = "00000",
                    exclude=False, include=False):
        self.set_ho(0)
        voice_file = None if call_type == CallType.SILENT else voice_file

        all_subscribers = self._get_filtered_subscribers(exclude=exclude, include=include)

        bts_list = self.get_bts()
        all_subscribers = [subscriber for subscriber in all_subscribers if subscriber.short_cell in bts_list]

        channels = self.get_channels()

        for bts in bts_list:
            print(f"BTS {bts}:\nTCH/F used {channels[bts][1]} total {channels[bts][0]}\n"
                  f"TCH/H used {channels[bts][3]} total {channels[bts][2]}\n"
                  f"SDCCH8 used {channels[bts][5]} total {channels[bts][4]}")

        CallTimestamp.start_calls()
        self.call(call_type, [subscriber.msisdn for subscriber in all_subscribers], call_from, voice_file)

    def send_message(self, sms_from: str, sms_to: str, sms_message: str, is_silent: bool):
        client = smpplib.client.Client(self._smpp_host, self._smpp_port)
        client.logger.setLevel(logging.DEBUG)

        # Print when obtain message_id
        client.set_message_sent_handler(
            lambda pdu: sys.stdout.write('sent {} {}\n'.format(pdu.sequence, pdu.message_id)))
        client.set_message_received_handler(
            lambda pdu: sys.stdout.write('delivered {}\n'.format(pdu.receipted_message_id)))

        client.connect()
        client.bind_transceiver(system_id=self._smpp_id, password=self._smpp_password)

        parts, encoding_flag, msg_type_flag = smpplib.gsm.make_parts(sms_message)

        try:
            sms_message.encode("ascii")
            coding = encoding_flag
        except:
            coding = smpplib.consts.SMPP_ENCODING_ISO10646

        self._logger.debug('Sending SMS "%s" to %s' % (sms_message, sms_to))
        for part in parts:
            pdu = client.send_message(
                msg_type=smpplib.consts.SMPP_MSGTYPE_USERACK,
                source_addr_ton=smpplib.consts.SMPP_TON_ALNUM,
                source_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
                source_addr=sms_from if len(sms_from) != 7 else sms_from + " ",
                dest_addr_ton=smpplib.consts.SMPP_TON_INTL,
                dest_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
                destination_addr=sms_to,
                short_message=part,
                data_coding=coding,
                esm_class=msg_type_flag,
                registered_delivery=True,
                protocol_id=64 if is_silent else 0,
            )
            self._logger.debug(pdu.sequence)

        client.state = smpplib.consts.SMPP_CLIENT_STATE_OPEN
        client.disconnect()

    def send_message_to_all(self, sms_from: str, sms_text: str, exclude: bool = False, include: bool = False,
                            is_silent: bool = False):
        self.set_ho(0)
        subscribers = self._get_filtered_subscribers(include=include, exclude=exclude)

        SmsTimestamp.update()

        for subscriber in subscribers:
            self.send_message(sms_from, subscriber.msisdn, sms_text, is_silent)

    def stop_calls(self):
        subprocess.run(["bash", "-c", "rm -f /var/spool/asterisk/outgoing/*"])
        subprocess.run(["bash", "-c", 'asterisk -rx "hangup request all"'])
        subprocess.run(["bash", "-c", "rm -f /var/spool/asterisk/outgoing/*"])
        time.sleep(1)
        subprocess.run(["bash", "-c", 'asterisk -rx "hangup request all"'])
        subprocess.run(["bash", "-c", "rm -f /var/spool/asterisk/outgoing/*"])
        CallTimestamp.stop_calls()

    def clear_hlr(self):
        current_path = os.path.dirname(os.path.abspath(__file__))
        subprocess.run(f"bash -c {current_path}/max_stop".split())
        archive_path = f"{current_path}/../tmp/hlr_archive"
        subprocess.run(f"mkdir -p {archive_path}".split())
        archive_file_name = f"hlr_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        db_path = "/var/lib/osmocom"
        subprocess.run(f"mv {db_path}/hlr.db {archive_path}/{archive_file_name}".split())
        subprocess.run(f"bash -c {current_path}/max_start".split())

    def to_850(self):
        current_path = os.path.dirname(os.path.abspath(__file__))
        subprocess.run(f"bash -c {current_path}/850".split())

    def to_900(self):
        current_path = os.path.dirname(os.path.abspath(__file__))
        subprocess.run(f"bash -c {current_path}/900".split())

    def start(self):
        current_path = os.path.dirname(os.path.abspath(__file__))
        subprocess.run(f"bash -c {current_path}/max_start".split())

    def stop(self):
        self.stop_calls()
        current_path = os.path.dirname(os.path.abspath(__file__))
        subprocess.run(f"bash -c {current_path}/max_stop".split())

    def _process_logs(self, lines: List[str]):
        # pre filter
        lines = [line.strip() for line in lines if ("Started Osmocom" in line or
                                                    (
                                                            " New transaction" in line and "trans(CC" in line) or " new state " in line or
                                                    (" Paging expired" in line and "trans(CC" in line) or
                                                    (
                                                            "tid-255,PAGING) tx MNCC_REL_CNF" in line and "trans(CC" in line)) and
                 "tid-8" not in line
                 ]

        all_logs = {}
        logs = {}
        start_time = None

        for line in lines:
            event = EventLine.create(line)
            if event is None:
                continue
            if event.is_started_event:
                if logs:
                    all_logs[f"{start_time}-{event.event_time}"] = logs
                    logs = {}
                start_time = event.event_time
            elif event.event.prev_status() == CallState.NEW:
                start_time = start_time or event.event_time
                new_call = Call(imsi=event.imsi, callref=event.callref, tid=event.tid)
                new_call.add_event(event.event, event.tid)
                if event.imsi not in logs:
                    logs[event.imsi] = {}
                if event.callref in logs[event.imsi]:
                    raise Exception("Same callref")

                logs[event.imsi][event.callref] = new_call

            elif event.callref == "0":
                if event.imsi in logs:
                    event_calls = logs[event.imsi]
                    for event_call in event_calls.values():
                        if event_call.tid == event.tid and event_call.get_last_state() not in [CallState.NULL,
                                                                                               CallState.BROKEN_BY_BTS,
                                                                                               CallState.NOT_AVAILABLE]:
                            event_call.add_event(event.event, event.tid)
                            break

            else:
                if event.imsi in logs and event.callref in logs[event.imsi]:
                    event_call = logs[event.imsi][event.callref]
                    event_call.add_event(event.event, event.tid)

        if logs:
            all_logs[f"{start_time}-"] = logs

        return all_logs

    def calls_status(self):
        result_records = {}
        since, until = CallTimestamp.get_period()

        if since is None:
            return result_records

        until_str = "" if until is None else f"--until='{until}'"
        res = subprocess.run(["bash", "-c", f"journalctl -u osmo-msc --since='{since}' {until_str}"],
                             capture_output=True)
        lines = res.stdout.decode("UTF-8").split("\n")
        records = self._process_logs(lines)

        if len(records) > 0:
            last_record = records[list(records.keys())[-1]]

            status_filter = {CallStatus.NOT_AVAILABLE, CallStatus.RINGING, CallStatus.ACTIVE, CallStatus.REJECT_BY_USER,
                             CallStatus.HANGUP}
            for imsi, calls in last_record.items():
                all_statuses = []
                for imsi_call in calls.values():
                    all_statuses.extend(imsi_call.statuses)
                result_records[imsi] = list(status_filter.intersection(all_statuses))
        return result_records

    def calls_status_show(self):
        result_records = {}
        since, until = CallTimestamp.get_period()

        if since is None:
            return result_records

        until_str = "" if until is None else f"--until='{until}'"
        res = subprocess.run(["bash", "-c", f"journalctl -u osmo-msc --since='{since}' {until_str}"],
                             capture_output=True)
        lines = res.stdout.decode("UTF-8").split("\n")
        records = self._process_logs(lines)

        if len(records) > 0:
            last_record = records[list(records.keys())[-1]]

            for imsi, calls in last_record.items():
                result_records[imsi] = [imsi_call.status for imsi_call in calls.values()]
        return result_records

    def sms_statuses(self):
        since, until = SmsTimestamp.get_period()

        res = subprocess.run(
            ["bash", "-c", f"journalctl -u osmo-msc --since='{since}' --until='{until}' | grep 'stat:DELIVRD'"],
            capture_output=True)
        lines = res.stdout.decode("UTF-8").split("\n")
        records = {}

        template = re.compile("IMSI-([0-9]+)")
        for line in lines:
            search_result = template.search(line)
            if search_result:
                imsi = search_result.group(1)
                if imsi not in records:
                    records[imsi] = []
                records[imsi].append("DELIVERED")
        return records

    def get_bts(self):
        ret = []
        cmd = f"show bts\r\n".encode()
        with Telnet(self._bsc_host, self._bsc_port_vty) as tn:
            tn.write(cmd)
            try:
                result = tn.expect([b"ACCH Repetition                  \r\nOsmoBSC", b"not available\)\r\nOsmoBSC"], 2)

                if result[0] != -1:  # success
                    result = [line.decode("utf-8").strip() for line in result[2].split(b"\r\n")]
                    bts = ""
                    re_bts = re.compile("is of sysmobts type in band.*has CI ([0-9]+) LAC ([0-9]+),")
                    for line in result:
                        match = re_bts.search(line)
                        if match:
                            bts = f"{match.group(2)}/{match.group(1)}"
                        if "OML Link state: connected" in line:
                            ret.append(bts)

            except EOFError as e:
                print(f"SDRError: {traceback.format_exc()}")

            return ret

    def get_channels(self):
        ret = {}
        cmd = f"show bts\r\n".encode()
        with Telnet(self._bsc_host, self._bsc_port_vty) as tn:
            tn.write(cmd)
            try:
                result = tn.expect([b"ACCH Repetition                  \r\nOsmoBSC", b"not available\)\r\nOsmoBSC"], 2)

                if result[0] != -1:  # success
                    result = [line.decode("utf-8").strip() for line in result[2].split(b"\r\n")]
                    bts = ""
                    re_bts = re.compile("is of sysmobts type in band.*has CI ([0-9]+) LAC ([0-9]+),")
                    for line in result:
                        match = re_bts.search(line)
                        if match:
                            bts = f"{match.group(2)}/{match.group(1)}"
                            ret[bts] = [0, 0, 0, 0, 0, 0]
                        if "Number of TCH/F channels total:" in line:
                            channels_count = int(line.replace("Number of TCH/F channels total:", "").strip())
                            ret[bts][0] = channels_count
                        if "Number of TCH/F channels used:" in line:
                            channels_count = int(line.replace("Number of TCH/F channels used:", "").strip())
                            ret[bts][1] = channels_count
                        if "Number of TCH/H channels total:" in line:
                            channels_count = int(line.replace("Number of TCH/H channels total:", "").strip())
                            ret[bts][2] = channels_count
                        if "Number of TCH/H channels used:" in line:
                            channels_count = int(line.replace("Number of TCH/H channels used:", "").strip())
                            ret[bts][3] = channels_count
                        if "Number of SDCCH8 channels total:" in line:
                            channels_count = int(line.replace("Number of SDCCH8 channels total:", "").strip())
                            ret[bts][4] = channels_count
                        if "Number of SDCCH8 channels used:" in line:
                            channels_count = int(line.replace("Number of SDCCH8 channels used:", "").strip())
                            ret[bts][5] = channels_count

            except EOFError as e:
                print(f"SDRError: {traceback.format_exc()}")

            return ret

    def set_ho(self, cnt=0):
        cmd = f"ho_count {cnt}\r\n".encode()
        with Telnet(self._bsc_host, self._bsc_port_vty) as tn:
            tn.write(cmd)

    def handover(self):
        channels = self.get_channels()

        bts_list = self.get_bts()
        if len(bts_list) != 2:
            return

        all_subscibers = self.get_subscribers()
        all_subscibers = [subscriber for subscriber in all_subscibers if subscriber.short_cell in bts_list]
        counter = {}
        for bts in bts_list:
            counter[bts] = len([1 for subscriber in all_subscibers if subscriber.short_cell == bts])

        if len(counter) > 1:
            bts_0, bts_1 = counter.items()
            bts_name_0, users_0 = bts_0
            bts_name_1, users_1 = bts_1
            total_users = users_0 + users_1
            total_channels_0 = channels[bts_name_0][0] + channels[bts_name_0][2]
            total_channels_1 = channels[bts_name_1][0] + channels[bts_name_1][2]
            if users_0 == users_1 or total_channels_0 == 0 or total_channels_1 == 0:
                return

            need_ho = int(max(users_0, users_1) - total_users / 2)
            self.set_ho(need_ho)

            call_bts = bts_name_0 if users_0 > users_1 else bts_name_1
            call_subscribers = [subscriber for subscriber in all_subscibers if subscriber.short_cell == call_bts]

            results = []
            threads = [threading.Thread(target=self._silent_call,
                                        args=(subscriber.msisdn, results)) for subscriber in call_subscribers]
            list(map(lambda x: x.start(), threads))

            for index, thread in enumerate(threads):
                self._logger.debug("Main    : before joining thread %d.", index)
                thread.join()
                self._logger.debug("Main    : thread %d done", index)

            ok_count = len([1 for result in results if result[0] == "ok"])
            self._logger.debug(f"Silent call with speech ok count {ok_count}/{len(results)}")

    def pprinttable(self, rows):
        if len(rows) > 0:
            headers = rows[0]
            lens = []
            for i in range(len(rows[0])):
                lens.append(len(max([x[i] for x in rows] + [headers[i]], key=lambda x: len(str(x)))))
            formats = []
            hformats = []
            for i in range(len(rows[0])):
                if isinstance(rows[0][i], int):
                    formats.append("%%%dd" % lens[i])
                else:
                    formats.append("%%-%ds" % lens[i])
                hformats.append("%%-%ds" % lens[i])
            pattern = " | ".join(formats)
            hpattern = " | ".join(hformats)
            separator = "-+-".join(['-' * n for n in lens])
            print(hpattern % tuple(headers))
            print(separator)

            for line in rows[1:]:
                print(pattern % tuple(line))


if __name__ == '__main__':
    arg_parser = ArgumentParser(description="Sdr control", prog="sdr")
    subparsers = arg_parser.add_subparsers(help="action", dest="action", required=True)

    parser_show = subparsers.add_parser("show", help="show subscribers")
    parser_show.add_subparsers(help="check subscribers with silent calls and clear inaccessible ones",
                               dest="check_before").add_parser("check_before")

    parser_sms = subparsers.add_parser("sms", help="send sms")
    parser_sms.add_argument("sms_type", choices=["normal", "silent"], help="normal or silent")
    parser_sms.add_argument("send_from", help="sender, use ascii only")
    parser_sms.add_argument("message", help="message text")
    sms_subparsers = parser_sms.add_subparsers(help="send to", dest="sms_send_to", required=True)
    sms_subparsers.add_parser("all", help="send to all subscribers")
    sms_subparsers.add_parser("all_exclude", help="send to all subscribers exclude list")
    sms_subparsers.add_parser("include_list", help="send to subscribers from include list")
    sms_list_parser = sms_subparsers.add_parser("list", help="send to subscribers from list")
    sms_list_parser.add_argument("subscribers", help="subscribers list", type=str, nargs='+')

    parser_call = subparsers.add_parser("call", help="call to subscribers")
    parser_call.add_argument("call_from", help="caller, use numeric string [3-15] only", type=str)

    call_type_parsers = parser_call.add_subparsers(help="call type", dest="call_type", required=True)
    silent_parser = call_type_parsers.add_parser("silent", help="silent call")
    silent_subparsers = silent_parser.add_subparsers(help="call to", dest="call_to", required=True)
    silent_subparsers.add_parser("all", help="call to all subscribers")
    silent_subparsers.add_parser("all_exclude", help="call to all subscribers exclude list")
    silent_subparsers.add_parser("include_list", help="call to subscribers from include list")
    silent_call_list_parser = silent_subparsers.add_parser("list", help="call to subscribers from list")
    silent_call_list_parser.add_argument("subscribers", help="subscribers list", type=str, nargs='+')
    #
    voice_parser = call_type_parsers.add_parser("voice", help="voice call")
    voice_parser.add_argument("file_type", choices=["gsm", "mp3"], help="voice file type")
    voice_parser.add_argument("file", type=str, help="voice file path")

    voice_call_subparsers = voice_parser.add_subparsers(help="call to", dest="call_to", required=True)
    voice_call_subparsers.add_parser("all", help="call to all subscribers")
    voice_call_subparsers.add_parser("all_exclude", help="call to all subscribers exclude list")
    voice_call_subparsers.add_parser("include_list", help="call to subscribers from include list")
    voice_call_list_parser = voice_call_subparsers.add_parser("list", help="call to subscribers from list")
    voice_call_list_parser.add_argument("subscribers", help="subscribers list", type=str, nargs='+')

    subparsers.add_parser("stop_calls", help="stop all calls (restart asterisk)")
    subparsers.add_parser("clear_hlr", help="clear hlr base (with BS restart)")
    subparsers.add_parser("silent", help="silent call with speech")
    subparsers.add_parser("850", help="900 -> 850")
    subparsers.add_parser("900", help="850 -> 900")
    subparsers.add_parser("start", help="start Umbrella")
    subparsers.add_parser("stop", help="stop Umbrella")
    subparsers.add_parser("calls_status", help="get last call status")
    subparsers.add_parser("calls_status_filtered", help="get last filtered call status")
    subparsers.add_parser("sms_status", help="get last sms status")
    subparsers.add_parser("bts", help="get active bts")
    subparsers.add_parser("channels", help="get total tch/f channel count")
    subparsers.add_parser("handover", help="Do handover")
    ho_parser = subparsers.add_parser("ho_count", help="Set need handover count")
    ho_parser.add_argument("count", help="need handover count", type=int)

    args = arg_parser.parse_args()

    sdr = Sdr(debug_output=True)

    action = args.action

    if action == "show":
        check_before = args.check_before is not None
        subscribers = sdr.get_subscribers(check_before=check_before, with_status=True)

        ch_info = [["BTS", "TCH/F total", "TCH/F used", "TCH/H total", "TCH/H used", "SDCCH8 total", "SDCCH8 used"]]

        for bts, ch in sdr.get_channels().items():
            ch_info.append([bts, *ch])
        print("\n\n")
        sdr.pprinttable(ch_info)

        print("\n")

        info = [["msisdn", "imsi", "imei", "last_ago", "cell", "ex", "in", "call status", "sms status"]]

        cells = {}
        cells_in = {}
        ops = {}
        current_path = os.path.dirname(os.path.abspath(__file__))
        with open(current_path + "/exclude_list") as f:
            exclude_list = [line.strip()[:14] for line in f.readlines()]
        with open(current_path + "/include_list") as f:
            include_list = [line.strip()[:14] for line in f.readlines()]

        call_records = sdr.calls_status_show()

        calls_info = {}
        delivered = 0

        for subscriber in sorted(subscribers, key=lambda x: x.imei in include_list):
            call_status = call_records[subscriber.imsi][-1].name if subscriber.imsi in call_records else "-------------"

            if call_status in calls_info:
                calls_info[call_status] += 1
            else:
                calls_info[call_status] = 1
            sms_status = subscriber.sms_status[-1] if len(subscriber.sms_status) > 0 else ""
            cells[subscriber.cell] = 1 if subscriber.cell not in cells else cells[subscriber.cell] + 1
            ops[subscriber.imsi[:5]] = 1 if subscriber.imsi[:5] not in ops else ops[subscriber.imsi[:5]] + 1

            delivered += 1 if len(sms_status) > 0 else 0

            info.append([subscriber.msisdn, subscriber.imsi, subscriber.imei, subscriber.last_seen, subscriber.cell,
                         '+' if subscriber.imei in exclude_list else '-',
                         '+' if subscriber.imei in include_list else '-', call_status, sms_status])

        print("\n\n")
        sdr.pprinttable(info)

        print(f"\nSMS delivered: {delivered}\n")
        print("\n", "\n ".join([str(item) for item in sorted(calls_info.items())]), "\n")

        exclude_count = len([1 for subscriber in subscribers if subscriber.imei in exclude_list])
        include_count = len([1 for subscriber in subscribers if subscriber.imei in include_list])
        print(f"  Total: {len(subscribers)}  Exclude: {exclude_count}/{len(subscribers) - exclude_count}"
              f"  Include: {include_count}/{len(subscribers) - include_count}")
        print("\n\n  BS cells:")
        for cell, cnt in sorted(cells.items(), key=lambda x: x[0]):
            exclude_count = len(
                [1 for subscriber in subscribers if subscriber.imei in exclude_list and subscriber.cell == cell])
            include_count = len(
                [1 for subscriber in subscribers if subscriber.imei in include_list and subscriber.cell == cell])
            print(f"      {cell}: {cnt}/ex {exclude_count}/in {include_count}")

        print("\n\n  Ops by IMEI:")
        ops_names = {"25062": "Tinkoff", "25001": "MTS ", "25002": "Megafon", "25099": "Beeline", "25020": "Tele2",
                     "25011": "Yota", "40101": "KZ KarTel", "40177": "KZ Aktiv"}
        for op, cnt in sorted(ops.items(), key=lambda x: x[0]):
            print(f"      {op} {ops_names[op] if op in ops_names else '':10}: {cnt}")

    elif action == "sms":
        SmsTimestamp.update()
        sms_from = args.send_from
        text = args.message
        is_silent = args.sms_type == "silent"
        sms_send_to = args.sms_send_to
        if sms_send_to == "all":
            sdr.send_message_to_all(sms_from, text, is_silent=is_silent)
        elif sms_send_to == "all_exclude":
            sdr.send_message_to_all(sms_from, text, exclude=True, is_silent=is_silent)
        elif sms_send_to == "include_list":
            sdr.send_message_to_all(sms_from, text, include=True, is_silent=is_silent)
        elif sms_send_to == "list":
            for subscriber in args.subscribers:
                sdr.send_message(sms_from, subscriber, text, is_silent=is_silent)

    elif action == "call":

        call_type = args.call_type
        file_type = args.file_type if hasattr(args, "file_type") else None
        call_to = args.call_to
        call_from = args.call_from
        voice_file = args.file if hasattr(args, "file") else None

        call_type = CallType.SILENT if call_type == "silent" else (CallType.GSM if file_type == "gsm" else CallType.MP3)

        if call_to == "all":
            sdr.call_to_all(call_type, voice_file, call_from)
        elif call_to == "all_exclude":
            sdr.call_to_all(call_type, voice_file, call_from, exclude=True)
        elif call_to == "include_list":
            sdr.call_to_all(call_type, voice_file, call_from, include=True)
        elif call_to == "list":
            CallTimestamp.start_calls()
            sdr.call(call_type, args.subscribers, call_from, voice_file)
    elif action == "stop_calls":
        sdr.stop_calls()
    elif action == "clear_hlr":
        sdr.clear_hlr()
    elif action == "silent":
        sdr.silent_call()
    elif action == "850":
        sdr.to_850()
    elif action == "900":
        sdr.to_900()
    elif action == "start":
        sdr.start()
    elif action == "stop":
        sdr.stop()
    elif action == "calls_status":
        subscribers = sdr.get_subscribers(with_status=True)
        prefix = "                              "
        prefix_end = "=============================="

        for subscriber in subscribers:
            print(f"{subscriber.imei}/{subscriber.imsi}:")
            for call in subscriber.calls_status:
                print(f"{prefix}{call}")
            print(prefix_end)
    elif action == "calls_status_filtered":
        results = sdr.calls_status()
        pprint.pprint(results)
    elif action == "sms_status":
        pprint.pprint(sdr.sms_statuses())
    elif action == "bts":
        pprint.pprint(sdr.get_bts())
    elif action == "channels":
        pprint.pprint(sdr.get_channels())
    elif action == "handover":
        sdr.handover()
    elif action == "ho_count":
        cnt = args.count
        sdr.set_ho(cnt)
