Tasks: TRAFFIC ANALYSIS EXERCISE: NEMOTODES
Source: Malware-Traffic-Analysis

1. Problem Statement

As part of a practical exercise from the Malware-Traffic-Analysis.net website, a network traffic dump (pcap file) dated 2024-11-26 was provided.

Environment baseline data:

    Local segment: 10.11.26.0/24 (addresses from 10.11.26.0 to 10.11.26.255)

    Active Directory domain: nemotodes.health, domain controller: 10.11.26.3

    Segment gateway: 10.11.26.1

Premise:
IDS/IPS alerts have triggered in the network, indicating a possible infection of a host with the NetSupport RAT remote access Trojan.

Task:
Analyze the pcap file, identify the infected machine, collect victim information, identify indicators of compromise (IOCs), and prepare an incident report.

2. Finding the Victim's IP Address

To isolate active connections to the outside world and filter out service noise, I applied the following composite filter:

				(http.request or tls.handshake.type eq 1) and !(ssdp)

It displays HTTP requests, TLS handshakes (the first packets of encrypted sessions), and excludes the SSDP protocol (which often masks background activity).
Among the results, all alerts and anomalous requests pointed to the same internal address – 10.11.26.183. This is the victim host.

3. Determining the Victim's MAC Address

I navigated to any packet with this IP (e.g., an ARP request or the initial Ethernet frame of a TCP session). The Ethernet Source field displayed the MAC address:

						MAC-address: d0:57:7b:ce:fc:8b

4. Clarifying the Hostname

To obtain the NetBIOS computer name, I applied a filter for the NBNS protocol:

							nbns

In the response packets for IP 10.11.26.183, I found an entry with the name DESKTOP-B8TQK49.

5. Identifying the Windows User Account

To find out which user the victim is logged in as, I filtered Kerberos traffic associated with this IP:

					kerberos && ip.addr eq 10.11.26.183

In the authorization fields (for example, in CNameString), I encountered the name oboomwald – this is the user's domain login.

6. Obtaining the Full User Name

To extract Active Directory attributes (first and last name), I used a special LDAP filter recommended in the training materials:

					ldap.AttributeDescription == "givenName"

This filter showed packets with the attributes givenName and sn (surname). This is how I established the victim's full name – Oliver Q. Boomwald.

7. Identifying the Source Domain and C2 Address

To detect suspicious external connections, I expanded the filter by adding SYN packets (the first segments of new TCP connections) and excluding SSDP:

		(http.request or tls.handshake.type eq 1 or (tcp.flags.syn eq 1 and tcp.flags.ack eq 0)) and !(ssdp)

Scrolling through the results in chronological order, I noticed that immediately after HTTP requests to classicgrand.com, requests to the domain modandcrackedp.com began (listed in some sources as modandcrackedapk.com). It was from this domain that a suspicious JavaScript file (presumably Udate.js) was downloaded, which is characteristic of the SmartApeSG (ZPHP) campaign.

Subsequently, all further activity (HTTP POST requests over port 443) was directed to the IP address 194.180.191.64 (and also to 194.180.191.164). These requests matched the alerts for NetSupport RAT activity (see alerts such as ETPRO TROJAN NetSupport RAT CnC Activity, etc.). Thus, I identified:

    Compromised source website: classicgrand.com

    Malicious domain (proxy / downloader): modandcrackedp.com

    NetSupport RAT C2 server: 194.180.191.64:443

8. Collecting Other IOCs

In addition to the primary C2, the following was also observed in the traffic:

    NetSupport GeoLocation requests (to 310.4.26.1:23 – probably test-related or erroneous, but I recorded this fact as part of the exercise).

    Multiple repeated POST requests to the path /fakerul.htm directed at the C2 address.

I included all listed artifacts in the final indicator list.

9. Conclusion

As a result of the pcap analysis, I confirmed the infection of host 10.11.26.183 (hostname DESKTOP-B8TQK49, user oboomwald – Oliver Q. Boomwald) with the NetSupport RAT remote access Trojan. The infection chain appears as follows:

    The user visits the compromised website classicgrand.com.

    The site injects a script that redirects to modandcrackedp.com.

    A fake update (Udate.js) is downloaded and executed from this domain, which in turn installs NetSupport RAT.

    The installed RAT establishes a persistent connection to the C2 server at 194.180.191.64:443, sending periodic POST requests and receiving commands.