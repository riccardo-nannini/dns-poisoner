from scapy.all import *
import datetime
import collections

dns_answers = collections.OrderedDict()
conf.sniff_promisc = 1
months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']

def parse_input_args(args): # parse input arguments
    iface = os.listdir('/sys/class/net')[0]
    tracefile = ""
    if "-i" in args:
        if "-r" in args:
            print("Do not use -r and -i together")
            exit(1)
        else:
            i = args.index("-i")
            if not (i + 1 >= len(args)):
                iface = args[i+1]
    elif "-r" in args:
        i = args.index("-r")
        if not (i + 1 >= len(args)):
            tracefile = args[i+1]
    else:
        print("Use either -r <tracefile> or -i <interface>")
        exit(1)
    return iface, tracefile

def log_attack(txid, domain, ip1, ip2): # log dns poisoning to file
    log = open("attack_log.txt", "a")
    date = datetime.datetime.now()
    output = "" + months[date.month-1] + " " + str(date.day) + " " + str(date.year) + " " + date.strftime("%H:%M:%S") + "\n"
    output = output + "TxID " + str(hex(txid)) + " Request " + domain + "\n"
    output = output + "Answer1 " + str(ip1) + "\n"
    output = output + "Answer2 " + str(ip2) + "\n\n"
    log.write(output)
    log.close()

def detection(pck): # callback function that performs dns poisoning detection
    ip = pck.getlayer("IP")
    udp = pck.getlayer("UDP")
    dns = pck.getlayer("DNS")
    if not ip or not udp or not dns:
        return
    if dns.qr:
        if not dns.an or not dns.an.rdata:
            return
        same_pck = dns_answers.get(dns.id)
        rdata = [dns.an[x].rdata for x in range(dns.ancount)] # extract every ip addr in response
        if same_pck: # check if txid is already present in dictionary
            if same_pck["answer_ip"] == rdata: #if retransmission of legit response (ips are the same) just ignore it
                return
            if same_pck["src_ip"] == ip.src and same_pck["dst_ip"] == ip.dst and same_pck["dport"] == udp.dport and same_pck["sport"] == udp.sport and same_pck["domain"] == str(dns.qd.qname)[2:-2]:
                print("DNS poisoning attempt detected")
                log_attack(dns.id, same_pck["domain"], same_pck["answer_ip"], rdata)
        else: # if txid is not in dictionary, add it
            dns_answers[dns.id] = {
                "domain" : str(dns.qd.qname)[2:-2],
                "answer_ip" : rdata,
                "src_ip" : ip.src,
                "dst_ip" : ip.dst,
                "sport" : udp.sport,
                "dport" : udp.dport,
            }
            if len(dns_answers.keys()) > 10000: # if dictionary has > 10.000 entries, it deletes the last one in FIFO order in order to avoid saturating the memory
                dns_answers.popitem(False)

def main():
    if os.getuid() != 0:
        print("I need root privileges to run")
        exit(1)

    iface, tracefile = parse_input_args(sys.argv[1:])

    if tracefile:
        sniff(count=0, filter="udp port 53", offline=tracefile, prn=detection)
    else:
        sniff(count=0, filter="udp port 53", monitor=True, prn=detection, iface=iface)

if __name__ == "__main__":
    main()
