import os
import pprint
from argparse import ArgumentParser

from sdr import Sdr, SmsTimestamp, CallType, CallTimestamp

if __name__ == '__main__':
    arg_parser = ArgumentParser(description="Sdr control", prog="sdr")
    subparsers = arg_parser.add_subparsers(help="action", dest="action", required=True)

    parser_show = subparsers.add_parser("show", help="show subscribers")
    parser_show.add_subparsers(help="check subscribers with silent calls and clear inaccessible ones",
                               dest="check_before").add_parser("check_before")

    parser_sms = subparsers.add_parser("sms", help="send sms")
    parser_sms.add_argument("sms_type", choices=["normal", "silent"], help="normal or silent")
    parser_sms.add_argument("sms_spam", choices=["once", "spam"], help="send once or spam")
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

    subparsers.add_parser("stop_sms", help="stop sms sending")

    switch_parser = subparsers.add_parser("switch_config", help="Switch config")
    switch_parser.add_argument("use_sms", help="1 - for sms, 0 - for calls", type=int)

    delete_delivered_parser = subparsers.add_parser("delete_delivered", help="Delete delivered SMS")
    delete_delivered_parser.add_argument("delete", help="1 - delete, 0 - not delete", type=int)

    args = arg_parser.parse_args()

    sdr = Sdr(debug_output=True)

    action = args.action

    if action == "show":
        check_before = args.check_before is not None
        subscribers = sdr.get_subscribers(check_before=check_before, with_status=True)

        channels = sdr.get_channels()
        bts_list = sdr.get_bts()
        channels = {bts_name: channel for bts_name, channel in channels.items() if bts_name in bts_list}
        if len(channels) > 0:
            ch_info = [["BTS", *(list(channels.values())[0].keys())]]

            for bts, ch in channels.items():
                ch_info.append([bts, *ch.values()])
            print("\n")
            sdr.pprinttable(ch_info)
            print("\n")

        info = [["msisdn", "imsi", "imei", "last_ago", "fail pr", "cell", "ex", "in", "call status", "sms status"]]

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

            info.append([subscriber.msisdn, subscriber.imsi, subscriber.imei, subscriber.last_seen, subscriber.failed_pagings, subscriber.cell,
                         '+' if subscriber.imei in exclude_list else '-',
                         '+' if subscriber.imei in include_list else '-', call_status, sms_status])

        sdr.pprinttable(info)

        print(f"\nSMS delivered: {delivered}\n")
        exclude_count = len([1 for subscriber in subscribers if subscriber.imei in exclude_list])
        include_count = len([1 for subscriber in subscribers if subscriber.imei in include_list])
        print(f"Total: {len(subscribers)}  Exclude: {exclude_count}/{len(subscribers) - exclude_count}"
              f"  Include: {include_count}/{len(subscribers) - include_count}\n")

        sdr.pprinttable([["Call status", "Count"], *sorted(calls_info.items())])
        print("\n")

        bs_cells = [["BS cell", "Count", "Excluded", "Included", "Good", "Not good"]]
        for cell, cnt in sorted(cells.items(), key=lambda x: x[0]):
            exclude_count = len(
                [1 for subscriber in subscribers if subscriber.imei in exclude_list and subscriber.cell == cell])
            include_count = len(
                [1 for subscriber in subscribers if subscriber.imei in include_list and subscriber.cell == cell])
            good_count = len([1 for subscriber in subscribers if subscriber.cell == cell
                              and subscriber.last_seen_int < 20])
            bs_cells.append([cell, cnt, exclude_count, include_count, good_count, cnt - good_count])
        sdr.pprinttable(bs_cells)

        ops_names = {"25062": "Tinkoff", "25001": "MTS ", "25002": "Megafon", "25099": "Beeline", "25020": "Tele2",
                     "25011": "Yota", "40101": "KZ KarTel", "40177": "KZ Aktiv"}
        print("\n")
        plmn_info = [[op, ops_names[op] if op in ops_names else '', cnt] for op, cnt in
                     sorted(ops.items(), key=lambda x: x[0])]
        sdr.pprinttable([["PLMN", "Operator", "Count"], *plmn_info])
        print("\n")

    elif action == "sms":
        SmsTimestamp().start()
        sms_from = args.send_from
        text = args.message
        is_silent = args.sms_type == "silent"
        sms_send_to = args.sms_send_to
        once = args.sms_spam == "once"
        if sms_send_to == "all":
            sdr.send_message_to_all(sms_from, text, is_silent=is_silent, once=once)
        elif sms_send_to == "all_exclude":
            sdr.send_message_to_all(sms_from, text, exclude=True, is_silent=is_silent, once=once)
        elif sms_send_to == "include_list":
            sdr.send_message_to_all(sms_from, text, include=True, is_silent=is_silent, once=once)
        elif sms_send_to == "list":
            sdr.send_message_to_list(sms_from, text, args.subscribers, is_silent=is_silent, once=once)

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
            sdr.call_to_list(call_type, args.subscribers, call_from, voice_file)
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
    elif action == "stop_sms":
        sdr.stop_sms()
    elif action == "switch_config":
        sdr.switch_config(args.use_sms == 1)
    elif action == "delete_delivered":
        sdr.delete_delivered_sms(args.delete == 1)
