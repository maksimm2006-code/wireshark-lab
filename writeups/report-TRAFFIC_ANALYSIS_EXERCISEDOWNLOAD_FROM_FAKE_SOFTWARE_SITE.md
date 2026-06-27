Tasks: TRAFFIC ANALYSIS EXERCISE:DOWNLOAD FROM FAKE SOFTWARE SITE
Source: Malware-Traffic-Analysis

1. Introduction

As a student specialising in network security, I completed a practical exercise in analysing malicious network traffic. The scenario is based on a real-world infection chain where a victim downloaded malware from a fake software distribution site. The provided pcap file contained all the relevant network activity.

The goal of this task was to identify the infected Windows client, gather host and user information, and pinpoint the malicious infrastructure (domains and IP addresses) involved in the attack.

2. Methodology and Analysis Steps

I used Wireshark to examine the pcap file. The approach was step-by-step, using targeted display filters to extract the required information.

2.1. Finding the IP Address of the Infected Client

To reduce background noise (such as SSDP broadcasts) and focus on client-initiated communication, I applied the following filter:

					(http.request or tls.handshake.type eq 1) and !(ssdp)

This shows all HTTP requests and TLS handshakes, excluding SSDP. Scanning the results, I noticed that all suspicious traffic – especially connections to the C2 server – originated from a single internal IP:

						Infected Windows client IP address: 10.1.17.215

2.2. Determining the MAC Address

With the IP address known, I clicked on any packet from 10.1.17.215 and expanded the Ethernet II header in the packet details pane. The source MAC address was displayed there:

							MAC address: 00:0d:b7:26:4a:74

2.3. Obtaining the Hostname

To retrieve the machine name, I filtered for DHCP traffic using:

								dhcp

In the DHCP request (or offer) packets, the "Host Name Option" field contained the computer's name:

							Hostname: DESKTOP-L8C5GSJ

2.4. Finding the User Account Name

For user identification, I searched for Kerberos authentication traffic (port 88) associated with the infected IP:

							kerberos && ip.addr eq 10.1.17.215

In one of the Kerberos ticket-granting tickets (TGT), the "CNameString" field revealed the username:

							User account name: shutchenson

2.5. Discovering the Fake Software Domain (Google Authenticator)

I suspected that the victim visited a fraudulent site to download the malware. To find the domain, I used the following filter to search for DNS queries containing the word "authenticator":

							dns contains "authenticator"

This revealed the domain used for the fake Google Authenticator download:

				Fake software domain: google.auauthenticator.barleson.appliante.net

2.6. Identifying C2 Server IP Addresses

To find the IP addresses of the servers that received the stolen data or issued commands, I used a broader filter to capture HTTP requests, TLS handshakes, and TCP SYN packets (which indicate new connection attempts):

		(http.request or tls.handshake.type eq 1 or (tcp.flags.syn eq 1 and tcp.flags.ack eq 0)) and !(ssdp)

By carefully analysing the decrypted (plaintext) HTTP packets and observing the timing of TCP handshakes, I noticed that suspicious SYN packets preceded the actual data exfiltration. The destination IP of these handshakes matched the C2 server.

					C2 server IP address: 5.252.153.241, 45.125.66.32, 45.125.66.252

3. Results Summary

	- IP address of infected Windows client: 10.1.17.215
	- MAC address: [insert MAC]
	- Hostname: [insert hostname]
	- User account name: [insert username]
	- Fake software domain (Google Authenticator): [insert domain]
	- C2 server IP address: [insert C2 IP]

4. Indicators of Compromise (IoCs)

	- Internal infected IP: 10.1.17.215
	- MAC address: [insert MAC]
	- Fake download domain: [insert domain]
	- C2 IP: [insert C2 IP]
	- Malware family: Lumma Stealer (based on alert context)

5. Conclusion

Through this exercise, I successfully identified the compromised Windows host, its user, the fraudulent download site, and the command-and-control server. The practical use of Wireshark filters – for HTTP, TLS, DHCP, DNS, and Kerberos – allowed me to piece together the infection chain. This experience has significantly improved my skills in network traffic analysis and incident investigation, which are essential for a career in cybersecurity.