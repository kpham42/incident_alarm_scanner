#!/usr/bin/python3
from scapy.all import TCP, IP, sniff, Raw
import argparse
import base64

#global count
COUNT = 0

#Function: packetcallback
#Inputs: packet
#Info: Retrieves the packet and detects intrusive network scans/visible username-password pairs.

def packetcallback(packet):
    try:
      retrieve(packet)
      for scan_type in ["null", "xmas", "fin", "nikto", "smb","rdp","vnc"]:
          scanner(packet, scan_type)
    except Exception as e:
      pass

#Function: scanner
#inputs: packet (pakcet file), scan_type (string)
#Info: Scans packet for the scan type provided, and inputs payload for non-stealthy scans only.

def scanner(packet, scan_type):
  payload = ""
  tcp, haslayer = packet[TCP], packet.haslayer

  if TCP in packet:
    payload = packet[TCP].load.decode("ascii").strip()
    
  if scan_type == "null" and tcp.flags == 0 and haslayer(TCP):
    alarm1(packet, "NULL Scan", "TCP")
  elif scan_type == "xmas" and tcp.flags == "FPU" and haslayer(TCP):
    alarm1(packet, "Xmas Scan", "TCP")
  elif scan_type == "fin" and tcp.flags == "F" and haslayer(TCP):
    alarm1(packet, "FIN Scan", "TCP")
  elif scan_type == "nikto" and tcp.dport == 80 and haslayer(TCP) and haslayer(Raw) and "Nikto" in packet.load.decode('utf-8'):
    alarm1(packet, "Nikito Scan", "HTTP", payload)
  elif scan_type == "smb" and tcp.dport in (445, 139, 137, 138) or tcp.sport in (445, 139, 137, 138):
    alarm1(packet, "SMB Scan", "TCP", payload)
  elif scan_type == "rdp" and tcp.dport == 3389 or tcp.sport == 3389:
    alarm1(packet,"RDP Scan", "TCP", payload)
  elif scan_type == "vnc" and tcp.dport in (5900, 5800, 5500, 5901, 5902) or tcp.sport in (5900, 5800, 5500, 5901, 5902):
        alarm1(packet, "VNC Scan", "TCP", payload)


#Function: retrive
#inputs: packet (pcap file)
#Info: Scans packet for instances of visible username-password pairs for HTTP, IMAP, and FTP protocols.

def retrieve(packet):
    try:
      load = packet[Raw].load.decode()
      if "Authorization: Basic " in load:
          encoded = load.split("Authorization: Basic ")[1].split("\r\n")[0]
          decoded = str(base64.b64decode(encoded), 'utf-8')
          username, password = decoded.split(":")
          alarm2(packet, "Usernames and passwords sent in-the-clear", "HTTP", f"Username: {username}, Password: {password}")
      elif packet[TCP].dport == 21:
        load = packet[TCP].load.decode("ascii").strip()
        for prefix in ("USER", "PASS"):
          if prefix in load:
            for lines in load.splitlines():
              line = lines.split()
              if prefix == line[0]:
                username = line[1]
                password = line[1]
                alarm2(packet, "Usernames and passwords sent in-the-clear", "FTP", f"Username: {username}, Password: {password}")
      elif packet[TCP].dport == 143 and "LOGIN" in load:
        load = packet[TCP].load.decode("ascii").strip()
        if "LOGIN" in load:
          for lines in load.splitlines():
            line = lines.split()
            if "LOGIN" == line[1]:
              username = line[2]
              password = line[3]
              alarm2(packet, "Usernames and passwords sent in-the-clear", "IMAP", f"Username: {username}, Password: {password}")
    except Exception as e:
        return

#Function: alarm1
#inputs: packet (packet file), scan (string), protocol (string), payload (string)
#Info: For network scans only. Prints out information regarding that scan type and payload if needed.

def alarm1(packet, scan, protocol, payload = ""):
  global COUNT
  COUNT += 1
  print("ALERT #" + str(COUNT) + ": " + scan + " is detected from " + str(packet[IP].src) + " (" + protocol + ")!\n" + payload)

#Function: alarm2
#inputs: packet (PCAP file), scan (string), protocol (string), username (string), password (string)
#Info: If login information is detected, this is triggered to print out that payload specifically.

def alarm2(packet, scan, protocol, username="", password=""):
    global COUNT
    COUNT += 1
    print("ALERT #" + str(COUNT) + ": " + scan + " is detected from " + str(packet[IP].src) + " (" + protocol + ")!" + " " + username + password)
# Terminal Arguments
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
