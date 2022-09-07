# :scorpion: DNS poisoner :scorpion:
This repository contains two different tools.<br>
[dns-inject](https://github.com/riccardo-nannini/dns-poisoner/blob/main/dns-inject.py) is a DNS injector which captures traffic from a network interface in promiscuous mode and inject forged responses to selected DNS A requests. <br>
[dns-detect](https://github.com/riccardo-nannini/dns-poisoner/blob/main/dns-detect.py) is a DNS poisoning detector. It captures traffic from a network interface in promiscuous mode and detects DNS poisoning attack attempts. The detection is based on identifying duplicate responses which contains different answers for the same domain's request.

## Inject :spider:

	python3 dns-inject.py [-i interface] [-h hostnames]
 - **-i**: Listen on network device interface (e.g., eth0). If not specified, a default one is selected. The same interface is also used for injecting forged packets.

- **-h**: Read a hostname file containing a list of IP address and hostname pairs specifying the hostnames to be hijacked. If ‘-h‘ is not specified, the injector forges replies for all observed requests with the local machine’s IP address as an answer.

## Detect :rotating_light:

	python3 dns-detect.py [-i interface | -r tracefile]
 - **-i**: Listen on network device interface (e.g., eth0). If not specified, a default one is selected. 

- **-r**: Read packets from tracefile (tcpdump format).

Once an attack is detected, a log will be created in a log file named **attack_log.txt**, containing information on the detected attack. The log file contains the date and time of the detected response, the DNS transaction ID, the attacked domain name, and the different IP addresses contained in the responses. For example:<br>

<p align="center">- March 7 2022 18:34:02</p>
<p align="center">- TxID 0x5cce Request www.example.com</p>
<p align="center">- IP from response #1</p>
<p align="center">- IP from response #2</p>

## Disclaimer :page_facing_up:

All information and software available on this repository are for educational purposes only. Usage of tools from this repository for attacking targets without prior mutual consent is illegal. It is the end user’s responsibility to obey all applicable local, state and federal laws.

## Developer :busts_in_silhouette:
 #### Riccardo Nannini :it:
- [Linkedin](https://www.linkedin.com/in/riccardo-nannini/), [Twitter](https://twitter.com/NanniniRiccardo)
