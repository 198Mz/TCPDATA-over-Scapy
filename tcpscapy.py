# CREATED BY 198Mz
# If you are using linux, then execute this before running the script: sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
# create for a server e.g.: nc -l -p 5555
# watch connection on server pc with: watch "netstat -an | grep -i 5555"

import time
import sys
from scapy.all import *


ip = IP(src=sys.argv[1], dst=sys.argv[2])
SYN = TCP(sport=1024, dport=5555, flags="S", seq=0)
packet = ip/SYN
SYNACK = sr1(packet)

ACK = TCP(sport=1024, dport=5555, flags="A", seq=SYNACK.ack, ack=SYNACK.seq + 1)
send(ip/ACK)

PUSH = TCP(sport=1024, dport=5555, flags="PA", seq=SYNACK.ack, ack=SYNACK.seq + 1)
PUSHACK = sr1(ip/PUSH/b"\x41\x0a")

time.sleep(5)
FIN = TCP(sport=1024, dport=5555, flags="FA", seq=PUSHACK.ack, ack=PUSHACK.seq)
FINACK = sr1(ip/FIN)

LASTACK = TCP(sport=1024, dport=5555, flags="A", seq=FINACK.ack, ack=FINACK.seq + 1)
send(ip/LASTACK)
