import logging
import os
import socket
import sys
from collections import namedtuple

import smpplib.client
import smpplib.consts
import smpplib.gsm
from osmopy.osmo_ipa import Ctrl


def connect(host, port):
    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sck.setblocking(1)
    sck.connect((host, port))
    return sck


def do_set_get(sck, var, value=None):
    (r, c) = Ctrl().cmd(var, value)
    sck.send(c)
    ret = sck.recv(4096)
    return (Ctrl().rem_header(ret),) + Ctrl().verify(ret, r, var, value)


def get_var(sck, var):
    (_, _, v) = do_set_get(sck, var)
    return v


def _leftovers(sck, fl):
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
            print("Got message:", Ctrl().rem_header(head))
            if len(tail) == 0:
                break
        return True
    return False


Subscriber = namedtuple('Subscriber', ['imsi', 'msisdn', 'imei'])


def get_subscribers():
    host = "localhost"
    port = 4255
    var = "subscriber-list-active-v1"

    sock = connect(host, port)
    _leftovers(sock, socket.MSG_DONTWAIT)
    (a, _, _) = do_set_get(sock, var)

    subscribers = a.decode("ascii").split()[3:]
    return [Subscriber(line.split(",")[0], line.split(",")[1], line.split(",")[2]) for line in subscribers]


def call(caller_extension, extension, voice_file):
    if not caller_extension:
        caller_extension = ""
    call_data = """Channel: SIP/GSM/{}
MaxRetries: 10
RetryTime: 10
WaitTime: 30
CallerID: {}
Application: Playback
Data: {}""".format(extension, caller_extension, voice_file)

    call_file = "{}.call".format(extension)
    with open(call_file, "w") as f:
        f.write(call_data)
        f.close()

    os.system("chown asterisk:asterisk {}".format(call_file))
    os.system("mv {} /var/spool/asterisk/outgoing/".format(call_file))


def send_message(source, dest, string):
    client = smpplib.client.Client('127.0.0.1', 2775)
    client.logger.setLevel(0)

    # Print when obtain message_id
    client.set_message_sent_handler(
        lambda pdu: sys.stdout.write('sent {} {}\n'.format(pdu.sequence, pdu.message_id)))
    client.set_message_received_handler(
        lambda pdu: sys.stdout.write('delivered {}\n'.format(pdu.receipted_message_id)))

    client.connect()
    client.bind_transceiver(system_id='OSMO-SMPP', password='1234')

    parts, encoding_flag, msg_type_flag = smpplib.gsm.make_parts(string)

    try:
        string.encode("ascii")
        coding = encoding_flag
    except:
        coding = smpplib.consts.SMPP_ENCODING_ISO10646

    logging.info('Sending SMS "%s" to %s' % (string, dest))
    for part in parts:
        pdu = client.send_message(
            msg_type=smpplib.consts.SMPP_MSGTYPE_USERACK,
            source_addr_ton=smpplib.consts.SMPP_TON_ALNUM,
            source_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
            source_addr=source,
            dest_addr_ton=smpplib.consts.SMPP_TON_INTL,
            dest_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
            destination_addr=dest,
            short_message=part,
            data_coding=coding,
            esm_class=msg_type_flag,
            # esm_class=smpplib.consts.SMPP_MSGMODE_FORWARD,
            registered_delivery=True,
        )
    logging.debug(pdu.sequence)

    client.state = smpplib.consts.SMPP_CLIENT_STATE_OPEN
    client.disconnect()


if __name__ == '__main__':

    command = sys.argv[1]

    if command == "show":
        if len(sys.argv) != 2:
            print("Args error")
            exit(0)

        subscribers = get_subscribers()

        print("\n")
        print("==================================================================")
        print("   msisdn       imsi               imei         ")
        print("==================================================================")

        for subscriber in subscribers:
            print(f"   {subscriber.msisdn}        {subscriber.imsi}    {subscriber.imei} ")
        print("===================================================================")
        print(f"  Total: {len(subscribers)}")

    elif command == "call":
        if len(sys.argv) != 2:
            print("Args error")
            exit(0)
        sound = "gubin"
        call_from = "00000"

        subscribers = [subscriber.msisdn for subscriber in get_subscribers()]

        for subscriber in subscribers:
            print(f"call to: {subscriber}")
            call(call_from, subscriber, sound)
        print(f"  Total: {len(subscribers)}")
    elif command == "call_one":
        if len(sys.argv) != 3:
            print("Args error")
            exit(0)
        sound = "gubin"
        call_from = "00000"

        call_to = sys.argv[2]
        print(f"call to: {call_to}")
        call(call_from, call_to, sound)

    elif command == "sms":
        if len(sys.argv) != 2:
            print("Args error")
            exit(0)

        name = "OsmoMSC"
        host = "127.0.0.1"
        port = 4254
        sms_from = "00000"
        sms_from = "center"
        text = "Привет"
        # text = sys.argv[2]

        subscribers = get_subscribers()
        # subscribers = ["11071"]
        for subscriber in subscribers:
            print(f"send sms: {subscriber.msisdn}")
            send_message(sms_from, subscriber.msisdn, text)
        print(f"  Total: {len(subscribers)}")
    else:
        print("Unknown command")
