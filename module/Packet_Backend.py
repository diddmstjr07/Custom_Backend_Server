from scapy.all import IP, TCP, sr1, ICMP, sendp, sniff, Raw, ARP, UDP, send
from scapy.layers.inet import RandShort
import threading
import os
import subprocess
import utils.database as DB
import re

subprocess.run(['pip', 'install', 'scapy', '-q'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def INNERIP():
    try:
        result = subprocess.run(['ifconfig'], stdout=subprocess.PIPE, text=True)
        lines = result.stdout.split('\n')
        for line in lines:
            ip_address = re.search(r'inet 192\.(\d+\.\d+\.\d+)', line)
            if ip_address:
                ip = ip_address.group(1)
                ip = "192." + str(ip)
        return ip
    except UnboundLocalError:
        print("\033[1m\033[31m" + "[ERROR]" + "\033[0m", "Internet Protocol is not connected")
        os._exit(0)

if os.getuid() != 0:
    print("\033[1m\033[31m" + "[ERROR]" + "\033[0m", "Please start Program as Root (sudo)")
    os._exit(0)

def callback(SRC, DST, SRC_PORT, DST_PORT):
    sta = DST
    des = SRC
    mes = Raw("200OK")
    st_port = DST_PORT
    de_port = SRC_PORT
    ip = IP(src=sta, dst=des)
    udp = UDP(dport=de_port, sport=st_port)
    packet = ip/udp/mes
    send(packet,verbose=0)

def error_filter(packet):
    if packet.haslayer(TCP):
        print( "\033[1m\033[92m" + "[LOG]" + "\033[0m", "TCP Packet Protocol is not Allowed", "\033[1m\033[31m" + "[404 ERROR]" + "\033[0m")
    elif packet.haslayer(ICMP):
        print("\033[1m\033[92m" + "[LOG]" + "\033[0m", "ICMP Packet Protocol is not Allowed", "\033[1m\033[31m" + "[404 ERROR]" + "\033[0m")
    elif packet.haslayer(ARP):
        print("\033[1m\033[92m" + "[LOG]" + "\033[0m", "ARP Packet Protocol is not Allowed", "\033[1m\033[31m" + "[404 ERROR]" + "\033[0m")

def packet_callback(packet):
    SRC = packet[IP].src
    DST = packet[IP].dst
    SRC_PORT = packet[UDP].sport
    DST_PORT = packet[UDP].dport
    DATA = str(packet[Raw].load)[2:-1]
    print("\033[1m\033[92m" + "[LOG]" + "\033[0m", "\033[93m" + f"{SRC}:{SRC_PORT}" + "\033[0m", "\033[1m" + "-->" + "\033[0m", "\033[93m" + f"{DST}:{DST_PORT}" + "\033[0m", "\033[1m\033[92m" + "[200 OK]" + "\033[0m")
    DB.Register(DATA, SRC, SRC_PORT)
    callback(SRC, DST, SRC_PORT, DST_PORT)

def sniffing(PORT, IP_ADD):
    sniff(filter=f"udp port {PORT} and not src host {IP_ADD}", prn=packet_callback)

def error_sniffing(PORT, IP_ADD):
    sniff(filter=f"not udp and port {PORT} and not src host {IP_ADD}", prn=error_filter)

def __all__(PORT):
    PORT = str(PORT)
    IP_ADD = INNERIP()
    print("\033[1m\033[92m" + "[LOG]" + "\033[0m", "Compile Completed...")
    print("\033[1m\033[92m" + "[LOG]" + "\033[0m", "Backend Platform Starting...")
    error_thread = threading.Thread(target=error_sniffing,args=(PORT,IP_ADD,))
    error_thread.start()
    sniffing(PORT,IP_ADD)

