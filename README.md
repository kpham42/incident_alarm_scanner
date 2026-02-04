# incident_alarm_scanner
An old school assignment from CS116 - Introduction to Security at Tufts University

## Incident Detection Scanner
I developed this Incident Detection Scanner as a Python-based security tool to monitor network traffic and identify common reconnaissance scans and insecure, clear-text credential transmissions. It utilizes the Scapy library to perform deep packet inspection (DPI) on either live traffic or pre-recorded PCAP files.

## My Scanner's Features
1. Network Scan Alarms
I programmed the scanner to monitor specific TCP flag configurations and port-specific traffic to identify potential threats:

2. NULL Scan: I detect packets where no TCP flags are set.

3. FIN Scan: I flag packets that have only the FIN flag set.

4. Xmas Scan: I look for packets with FIN, PSH, and URG flags set, which are used to bypass certain firewalls.

5. Nikto: My scanner identifies the signature of the Nikto web vulnerability scanner within HTTP headers.

6. Service Probing: I monitor for scans targeting common lateral movement ports such as SMB (445), RDP (3389), and VNC (5900+).

## Credential Extraction
I designed the tool to catch "in-the-clear" transmissions to demonstrate protocol insecurity:

**HTTP:** I automatically decode "Authorization: Basic" headers using base64 to reveal the original username:password.

**FTP & IMAP:** I parse command strings like USER, PASS, and LOGIN to extract raw credentials from the payload.

## How to Use My Tool
### Prerequisites
- Python 3.x.
- The scapy library.

## Running the Scanner
### To sniff live traffic on your default or chosen interface:
`sudo ./alarm.py -i eth0`
### To analyze a specific PCAP file for historical incidents:
`python3 alarm.py -r evidence.pcap`
