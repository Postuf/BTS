import logging
import os
import socket
import sys
import threading
from argparse import ArgumentParser
from collections import namedtuple
from datetime import datetime
from enum import Enum
from typing import Optional

import smpplib.client
import smpplib.consts
import smpplib.gsm
from osmopy.osmo_ipa import Ctrl
from telnetlib import Telnet
import subprocess

Subscriber = namedtuple('Subscriber', ['imsi', 'msisdn', 'imei', 'last_seen', 'cell'])


class CallType(Enum):
    MP3 = 1,
    GSM = 2,
    SILENT = 3


class Sdr:

    def __init__(self, msc_host: str = "localhost", msc_port_ctrl: int = 4255, msc_port_vty: int = 4254,
                 smpp_host: str = "localhost", smpp_port: int = 2775, smpp_id: str = "OSMO-SMPP",
                 smpp_password: str = "1234", debug_output: bool = False):
        self._msc_host = msc_host
        self._msc_port_ctrl = msc_port_ctrl
        self._msc_port_vty = msc_port_vty
        self._smpp_host = smpp_host
        self._smpp_port = smpp_port
        self._smpp_id = smpp_id
        self._smpp_password = smpp_password
        self._logger = logging.getLogger("SDR")

        if debug_output:
            self._logger.setLevel(logging.DEBUG)
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)

    def _leftovers(self, sck, fl):
        """
        Read outstanding data if any according to flags
        """
        try:
            data = sck.recv(1024, fl)
        except socket.error as _:
            return False
        if len(data) != 0:
            tail = data
            while True:
                (head, tail) = Ctrl().split_combined(tail)
                self._logger.debug("Got message:", Ctrl().rem_header(head))
                if len(tail) == 0:
                    break
            return True
        return False

    def _do_set_get(self, sck, var, value=None):
        (r, c) = Ctrl().cmd(var, value)
        sck.send(c)
        ret = sck.recv(4096)
        return (Ctrl().rem_header(ret),) + Ctrl().verify(ret, r, var, value)

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
                pass
            return "error"

    def _get_subscribers(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setblocking(True)
            s.connect((self._msc_host, self._msc_port_ctrl))
            self._leftovers(s, socket.MSG_DONTWAIT)
            (a, _, _) = self._do_set_get(s, "subscriber-list-active-v1")

            def subscriber_from_string(subscriber_string):
                elements = subscriber_string.split(",")
                return Subscriber(elements[0], elements[1], elements[2], elements[3], elements[4])

            subscribers = a.decode("ascii").split()[3:]
            return [subscriber_from_string(line) for line in subscribers]

    def _clear_expired(self):
        subscribers = self._get_subscribers()
        self._logger.debug(subscribers)
        chunk_size = 10
        chunks = [subscribers[i:i + chunk_size] for i in range(0, len(subscribers), chunk_size)]
        for chunk in chunks:
            threads = [threading.Thread(target=self._check_msisdn, args=(subscriber.msisdn,)) for subscriber in chunk]
            list(map(lambda x: x.start(), threads))

            for index, thread in enumerate(threads):
                self._logger.debug("Main    : before joining thread %d.", index)
                thread.join()
                self._logger.debug("Main    : thread %d done", index)

    def get_subscribers(self, check_before: bool = False):
        if check_before:
            self._clear_expired()
        return self._get_subscribers()

    def call(self, call_type: CallType, call_to: str, call_from: str = "00000", voice_file: Optional[str] = None):
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

        application = "Playback" if call_type == CallType.GSM else (
            "MP3Player" if call_type == CallType.MP3 else "Hangup")
        data = "" if call_type == CallType.SILENT else f"\nData: {voice_file}"

        call_data = f"Channel: SIP/GSM/{call_to}\n" \
                    f"MaxRetries: 500\n" \
                    f"RetryTime: 1\n" \
                    f"WaitTime: 30\n" \
                    f"CallerID: {call_from}\n" \
                    f"Application: {application}\n" \
                    + data

        call_file = f"{call_to}.call"
        with open(call_file, "w") as f:
            f.write(call_data)
            f.close()

        os.system(f"chown asterisk:asterisk {call_file}")
        os.system(f"mv {call_file} /var/spool/asterisk/outgoing/")

    def call_to_all(self, call_type: CallType = CallType.GSM, voice_file: str = "gubin", call_from: str = "00000",
                    exclude=False):
        voice_file = None if call_type == CallType.SILENT else voice_file
        exclude_list = []
        if exclude:
            current_path = os.path.dirname(os.path.abspath(__file__))
            with open(current_path + "/exclude_list") as f:
                exclude_list = [line.strip()[:14] for line in f.readlines()]

        for subscriber in self.get_subscribers():
            if subscriber.imei not in exclude_list:
                self.call(call_type, subscriber.msisdn, call_from, voice_file)

    def send_message(self, sms_from: str, sms_to: str, sms_message: str):
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
                source_addr=sms_from,
                dest_addr_ton=smpplib.consts.SMPP_TON_INTL,
                dest_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
                destination_addr=sms_to,
                short_message=part,
                data_coding=coding,
                esm_class=msg_type_flag,
                # esm_class=smpplib.consts.SMPP_MSGMODE_FORWARD,
                registered_delivery=True,
            )
            self._logger.debug(pdu.sequence)

        client.state = smpplib.consts.SMPP_CLIENT_STATE_OPEN
        client.disconnect()

    def send_message_to_all(self, sms_from: str, sms_text: str, exclude: bool = False):
        subscribers = self.get_subscribers()

        if exclude:
            current_path = os.path.dirname(os.path.abspath(__file__))
            with open(current_path + "/exclude_list") as f:
                exclude_list = [line.strip()[:14] for line in f.readlines()]

        for subscriber in subscribers:
            if subscriber.imei not in exclude_list:
                self.send_message(sms_from, subscriber.msisdn, sms_text)

    def stop_calls(self):
        subprocess.run("sudo systemctl stop asterisk".split())
        subprocess.run(["bash", "-c", "rm -f /var/spool/asterisk/outgoing/*"])
        subprocess.run("sudo systemctl start asterisk".split())

    def clear_hlr(self):
        current_path = os.path.dirname(os.path.abspath(__file__))
        subprocess.run(f"bash -c {current_path}/max_stop".split())
        archive_path = f"{current_path}/../tmp/hlr_archive"
        subprocess.run(f"mkdir -p {archive_path}".split())
        archive_file_name = f"hlr_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        db_path = "/var/lib/osmocom"
        subprocess.run(f"mv {db_path}/hlr.db {archive_path}/{archive_file_name}".split())
        subprocess.run(f"bash -c {current_path}/max_start".split())


if __name__ == '__main__':
    arg_parser = ArgumentParser(description="Sdr control", prog="sdr")
    subparsers = arg_parser.add_subparsers(help="action", dest="action", required=True)

    parser_show = subparsers.add_parser("show", help="show subscribers")
    parser_show.add_subparsers(help="check subscribers with silent calls and clear inaccessible ones",
                               dest="check_before").add_parser("check_before")

    parser_sms = subparsers.add_parser("sms", help="send sms")
    parser_sms.add_argument("send_from", help="sender, use ascii only")
    parser_sms.add_argument("message", help="message text")
    sms_subparsers = parser_sms.add_subparsers(help="send to", dest="sms_send_to", required=True)
    sms_subparsers.add_parser("all", help="send to all subscribers")
    sms_subparsers.add_parser("all_exclude", help="send to all subscribers exclude list")
    sms_list_parser = sms_subparsers.add_parser("list", help="send to subscribers from list")
    sms_list_parser.add_argument("subscribers", help="subscribers list", type=str, nargs='+')

    parser_call = subparsers.add_parser("call", help="call to subscribers")
    parser_call.add_argument("call_from", help="caller, use numeric string [3-15] only", type=str)

    call_type_parsers = parser_call.add_subparsers(help="call type", dest="call_type", required=True)
    silent_parser = call_type_parsers.add_parser("silent", help="silent call")
    silent_subparsers = silent_parser.add_subparsers(help="call to", dest="call_to", required=True)
    silent_subparsers.add_parser("all", help="call to all subscribers")
    silent_subparsers.add_parser("all_exclude", help="call to all subscribers exclude list")
    silent_call_list_parser = silent_subparsers.add_parser("list", help="call to subscribers from list")
    silent_call_list_parser.add_argument("subscribers", help="subscribers list", type=str, nargs='+')
    #
    voice_parser = call_type_parsers.add_parser("voice", help="voice call")
    voice_parser.add_argument("file_type", choices=["gsm", "mp3"], help="voice file type")
    voice_parser.add_argument("file", type=str, help="voice file path")

    voice_call_subparsers = voice_parser.add_subparsers(help="call to", dest="call_to", required=True)
    voice_call_subparsers.add_parser("all", help="call to all subscribers")
    voice_call_subparsers.add_parser("all_exclude", help="call to all subscribers exclude list")
    voice_call_list_parser = voice_call_subparsers.add_parser("list", help="call to subscribers from list")
    voice_call_list_parser.add_argument("subscribers", help="subscribers list", type=str, nargs='+')

    subparsers.add_parser("stop_calls", help="stop all calls (restart asterisk)")
    subparsers.add_parser("clear_hlr", help="clear hlr base (with BS restart)")

    args = arg_parser.parse_args()

    sdr = Sdr(debug_output=True)

    action = args.action

    if action == "show":
        check_before = args.check_before is not None
        subscribers = sdr.get_subscribers(check_before)

        print("\n")
        print("====================================================================================")
        print("   msisdn       imsi               imei           last_ago     cell          exclude")
        print("====================================================================================")

        cells = {}
        ops = {}
        exclude_list = []
        current_path = os.path.dirname(os.path.abspath(__file__))
        with open(current_path + "/exclude_list") as f:
            exclude_list = [line.strip()[:14] for line in f.readlines()]


        for subscriber in sorted(subscribers, key=lambda x: x.imei in exclude_list):
            print(f"   {subscriber.msisdn}        {subscriber.imsi}    {subscriber.imei} {subscriber.last_seen:>6}       {subscriber.cell}      {'+' if subscriber.imei in exclude_list else '-'}")
            cells[subscriber.cell] = 1 if subscriber.cell not in cells else cells[subscriber.cell] + 1
            ops[subscriber.imsi[:5]] = 1 if subscriber.imsi[:5] not in ops else ops[subscriber.imsi[:5]] + 1
        print("====================================================================================")
        exclude_count = len([1 for subscriber in subscribers if subscriber.imei in exclude_list])
        print(f"  Total: {len(subscribers)}  Exclude: {exclude_count}  Include : {len(subscribers) - exclude_count}")
        print("\n\n  BS cells:")
        for cell, cnt in cells.items():
            print(f"      {cell}: {cnt}")
        print("\n\n  Ops by IMEI:")
        ops_names = {"25062": "Tinkoff","25001": "MTS ", "25002": "Megafon", "25099": "Beeline", "25020": "Tele2", "25011": "Yota", "40101": "KZ KarTel", "40177": "KZ Aktiv"}
        for op, cnt in sorted(ops.items(), key=lambda x: x[0]):
            print(f"      {op} {ops_names[op] if op in ops_names else '':10}: {cnt}")

    elif action == "sms":
        sms_from = args.send_from
        text = args.message
        sms_send_to = args.sms_send_to
        if sms_send_to == "all":
            sdr.send_message_to_all(sms_from, text)
        elif sms_send_to == "all_exclude":
            sdr.send_message_to_all(sms_from, text, exclude=True)
        elif sms_send_to == "list":
            for subscriber in args.subscribers:
                sdr.send_message(sms_from, subscriber, text)

    elif action == "call":

        call_type = args.call_type
        file_type = args.file_type if hasattr(args, "file_type") else None
        call_to = args.call_to
        call_from = args.call_from
        voice_file = args.file if hasattr(args, "file") else None

        call_type = CallType.SILENT if call_type == "silent" else (CallType.GSM if file_type == "gsm" else CallType.MP3)

        if call_to == "all":
            sdr.call_to_all(call_type, voice_file, call_from)
        if call_to == "all_exclude":
            sdr.call_to_all(call_type, voice_file, call_from, exclude=True)
        elif call_to == "list":
            for subscriber in args.subscribers:
                sdr.call(call_type, subscriber, call_from, voice_file)
    elif action == "stop_calls":
        sdr.stop_calls()
    elif action == "clear_hlr":
        sdr.clear_hlr()
