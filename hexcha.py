#!/bin/usr/python
#
# learning packet headers
# Derek Petersen 6/30/2019
# Modify random IP function to include creation
# Start with ICMP header next
#  -Allow '0x' in answers via clean() function

import random
from os import system
import re
import time

# Set string values here for checking answers to questions below that require string answers
# and cannot be mathed well
# Then below write random loops for questions regarding the various header parts
etypedict = {"0800": "ipv4", "0806": "arp", "8100": "vlan", "86DD": "ipv6", "88A4": "ethercat"}
ip_proto_dict = {"01": "icmp", "06": "tcp", "11": "udp", "10": "chaos"}
icmp_type_code = {"0000": "Reply", "0300": "Network Unreachable", "0301": "Host Unreachable", "0302": "Protocol Unreachable", "0303": "Port Unreachable", "0800": "Request", "0b00": "TTL expired", "0b01": "Fragment time exceeded"}

def clear():
    system('clear')

#clean up answer input, remove '0x' and make lower case
def clean(answer):
    clean = answer.lower().translate(None, '0x')
    return(clean)

def getrandom():
    ran = random.randrange(10**80)
    return "%x" % ran

#get random hex chars between specified decimal arguments . ex. 0,65535,4 for 2 bytes
def getrandomhex(low,high,count):
    randomhex = '{0:0{1}x}'.format(random.randrange(low,high),count)
    return randomhex

#build IPs and convert to hex and back to decimal octal notation
def IPaddy(switch, val):
    #convert hex IP to decimal, expecting 'xxxx xxxx' format
    if switch == "dec":
        ip = str(int(val[0:2], 16)) + "." + str(int(val[2:4], 16)) + "." + str(int(val[5:7], 16)) + "." + str(int(val[7:9], 16))
    return ip


#format packet to look like tcpdump data
def displaypacket(packetdata):
    addnewlines = re.sub("(.{0,40})", "\\t0x0000:  \\1\n", packetdata, 0, re.DOTALL) 
    i = 0
    dumpformat = ""
    # change the hex line id to reflect the correct line (0x0030 for line 3 or starting hex char #48)
    for line in addnewlines.splitlines():
         dumpformat += re.sub("0x\d{4}", "0x00"+str(i)+"0", line) + "\n"
         i += 1
    return dumpformat

#build ethernet header
def ethhdr():
    H=getrandom()
    dstmac = (H[:4] + " " + H[4:8] + " " + H[8:12])
    srcmac = (H[12:16] + " " + H[16:20] + " " + H[20:24])
    etype = random.choice(etypedict.items())
    return (dstmac + " " +  srcmac + " " + etype[0], etype, dstmac, srcmac)

#build ipv4 header
def ipv4hdr(prototype = None):
    ver_ihl_DSCP_ECN = '4500'
    tot_length = str(getrandomhex(20,1500,4))
    ident = str(getrandomhex(0,65535,4))
    flags_frag = '0000'
    ttl = getrandomhex(60,128,2)
    proto_dict = random.choice(ip_proto_dict.items())
    proto = proto_dict[0]
    proto_ascii = proto_dict[1]
    cksm = str(getrandomhex(0,65535,4))
    ips = ('c0a8 5301', 'c0a8 0043',  '0a00 011b', '441b 0b3a', '0837 1702', '1b36 9825', '2679 3c63', '5bdf c741', 'b93b 89b1')
    src_ip = random.choice(ips)
    dst_ip = random.choice(ips)
    if prototype is not None:
        if prototype == "icmp":
            proto = '01'
            print(proto)
        elif prototype == "tcp":
            proto = '06'
    return (ver_ihl_DSCP_ECN + " " +  tot_length + " " + ident + " " + flags_frag + " " + ttl + proto + " " + cksm + " " + src_ip + " " + dst_ip, tot_length, ident, ttl, proto, cksm, src_ip, dst_ip, proto_ascii)

#build ipv6 header
#build tcp header

def tcphdr():
    src_port = str(getrandomhex(0,65500,4))
    dst_port = str(getrandomhex(0,65500,4))
    sequence_nbr = (str(getrandomhex(0,65500,4)) + " " + str(getrandomhex(0,65500,4)))
    ack_nbr = (str(getrandomhex(0,65500,4)) + " " + str(getrandomhex(0,65500,4)))
    flags_dict = {"5011": "AF","5002": "S","5014": "AR", "5029": "UPF", "5012": "AS"}
    hdr_lgth_flags = random.choice(flags_dict.items())
    window_size = "faf0"
    cksm = "7b0f"
    urgent_pointer = "0000"
    return (src_port + " " + dst_port + " " + sequence_nbr + " " + ack_nbr + " " + hdr_lgth_flags[0] + " " + window_size + " " + cksm + " " + urgent_pointer, hdr_lgth_flags)

def tcptest():
    score = 0
    while score < 10:
        clear()
        tcpvar = tcphdr()
        packetdata = (ethhdr()[0] + " " + ipv4hdr("tcp")[0] + " " + str(tcpvar[0]))
        correctflags = str(tcpvar[1][1])
        print displaypacket(packetdata)
        answer = raw_input('\nCurrent Score: ' + str(score) + '\nWhich TCP flags are set in this packet? example: for ACK and SYN enter AS\n') 
        if answer.lower() == correctflags.lower():
            print("correct")
            time.sleep( .5 )
            score += 1
        else:
            raw_input("incorrect, 0x" + str(tcpvar[1][0])[2:4] + " = " + str(tcpvar[1][1]))
            tcptest()
        if score > 9:
            return "passed"

#build udp header
#build icmp header
def icmphdr():
    type_code = random.choice(icmp_type_code.items())
    checksum = str(getrandomhex(0,65535,4))
    return (type_code[0], checksum)


def icmptest():
    score = 0
    randchoice = 0 
    while score < 10:
        clear()
        icmpvar = icmphdr()
        correct_type_hex = icmpvar[0][:2]
        correct_code_hex = icmpvar[0][2:4]
        packetdata = (ethhdr()[0] + " " + ipv4hdr("icmp")[0] + " " + str(icmpvar[0]) + " " + str(icmpvar[1]))
        print displaypacket(packetdata)
        correctstr = str(icmp_type_code[icmpvar[0]]).lower()
        answer = raw_input('\nCurrent Score: ' + str(score) + '\nIs this a "request", "reply", "network unreachable", "host unreachable", "procotol unreachable", "port unreachable", "TTL expired" or "fragment time exceeded" message? ')
        if answer.lower() == correctstr.strip():  # fix blank line as correct!
            print("correct")
            time.sleep( .5 )
            score += 1
        else:
            raw_input("Wrong, " + icmpvar[0] + " = " + correctstr)
            icmptest()

#EtherType challenge - currently displays only the ethhdr
def ethtest():
    score = 0
    lastans = ""

    while score < 10:
        clear()
        ethvar = ethhdr()
        correct_type_hex = ethvar[1][0]
        correct_type_str = etypedict[ethvar[1][0]]
        print displaypacket(ethvar[0])
        answer = raw_input('\nCurrent Score: ' + str(score) + '\nWhat is the EtherType of this ethernet header? ')   #use input() for python3
        feedback = ",'0x" + correct_type_hex + "' = " + str(correct_type_str)
        if answer.lower() == correct_type_str:
            score += 1
        else:
            print("Wrong" + feedback)
            raw_input("press enter to continue...")
            score = 0
    return ('passed')

#IPv4 challenge
def ipv4test():
    lastans = ""
    score = 0
    randchoice = 0
    preventmultiIP = 0
    while score < 10:
        clear()
        ipv4_hdr = ipv4hdr()
        packetdata = (ethhdr()[0] + " " + ipv4_hdr[0])
        print displaypacket(packetdata)
        print("\n")
        #prevent same question twice in a row and more than one ip conversion question
        randvalues = [1,2,3,4,5]
        randnew = randvalues
        if randchoice in (4,5):
            preventmultiIP = 1
        if preventmultiIP == 1:
            randnew.remove(4)
            randnew.remove(5)
        if randchoice != 0 and randchoice not in (4,5):
            randnew.remove(randchoice)
        randchoice = random.choice(randnew)

        if randchoice == 1:
            #IP Protocol Question
            correct_proto_hex = ipv4_hdr[4]
            correct_proto_str = ipv4_hdr[8]
            answer = raw_input('Current Score: ' + str(score) + '\nWhat is the IP protocol of this packet header? ')
            feedback = ",'0x" + correct_proto_hex + "' = " + str(correct_proto_str)
            if clean(answer) == correct_proto_str:
                score += 1
            else:
                print("incorrect" + feedback)
                raw_input("press enter to continue...")
                ipv4test()

        if randchoice == 2:
            #TTL Question
            correct_ttl_hex = ipv4_hdr[3]
            correct_ttl_dec = int(ipv4_hdr[3], 16)
            answer = raw_input('Current Score: ' + str(score) + '\nWhat is the *decimal* TTL value of this packet? ')
            feedback = ", '0x" + correct_ttl_hex + "' = " + str(correct_ttl_dec)
            if clean(answer) == str(correct_ttl_dec):
                score += 1
            else:
                print("incorrect" + feedback)
                raw_input("press enter to continue...")
                ipv4test()

        if randchoice == 3:
            #Checksum Question
            correct_cksm_hex = ipv4_hdr[5]
            answer = raw_input('Current Score: ' + str(score) + '\nWhat is the *hex* checksum value of this packet? ')
            feedback = ", '0x" + correct_cksm_hex + "' " + "is the checksum value"
            if clean(answer) == correct_cksm_hex:
                score += 1
            else:
                print("incorrect" + feedback)
                raw_input("press enter to continue...")
                ipv4test()

        if randchoice == 4:
            #SourceIP Question
            correct_src_ip_hex = ipv4_hdr[6]
            correct_src_ip_dec = IPaddy("dec", ipv4_hdr[6])
            answer = raw_input('Current Score: ' + str(score) + '\nWhat is the source IP address, in standard decimal notation, of this packet? ')
            feedback = ", '0x" + correct_src_ip_hex + "' = " + correct_src_ip_dec
            if str(clean(answer)) == str(correct_src_ip_dec):
                score += 1
            else:
                print("Wrong" + feedback)
                raw_input("press enter to continue...")
                ipv4test()

        if randchoice == 5:
            #DestinationIP Question
            correct_dst_ip_hex = ipv4_hdr[7]
            correct_dst_ip_dec = IPaddy("dec", ipv4_hdr[7])
            answer = raw_input('Current Score: ' + str(score) + '\nWhat is the destination IP address, in standard decimal notation, of this packet? ')
            feedback = ", '0x" + correct_dst_ip_hex + "' = " + correct_dst_ip_dec
            if clean(answer) == correct_dst_ip_dec:
                score += 1
            else:
                print("Wrong" + feedback)
                raw_input("press enter to continue...")
                ipv4test()

    return("passed")

#game menu
print("To start playing, press enter. Or select an option to jump ahead.")
game_select = raw_input('\n<enter> to start\n"1" for ethernet\n"2" for IPv4\n"3" for ICMP\n"4" for TCP\n')
if game_select == "":
    if ethtest() == "passed":
        raw_input("Great work, now for IPv4 headers...")
        if ipv4test() == "passed":
            raw_input("Great work, now for ICMP headers...")
            if icmptest() == "passed":
                raw_input("Great work, on to TCP headers...")
                if tcptest() == "passed":
                    raw_input("Great work, you win for now...")
if game_select == "1":
    ethtest()
    print("Nice work, you win!")
if game_select == "2":
    ipv4test()
    print("Nice work, you win!")
if game_select == "3":
    icmptest()
    print("Nice work, you win!")
if game_select == "4":
    tcptest()
    print("Nice work, you win!")
