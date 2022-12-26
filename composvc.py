import re

port_data = {
    1: {"service_name": "tcpmux", "transport_protocol": "TCP", "description": "TCP port service multiplexer"},
    5: {"service_name": "rje", "transport_protocol": "TCP", "description": "Remote Job Entry"},
    7: {"service_name": "echo", "transport_protocol": "TCP, UDP", "description": "Echo service"},
    9: {"service_name": "discard", "transport_protocol": "TCP", "description": "Null service for connection testing"},
    11: {"service_name": "systat", "transport_protocol": "TCP", "description": "System Status service for listing connected ports"},
    13: {"service_name": "daytime", "transport_protocol": "TCP", "description": "Sends date and time to requesting host"},
    17: {"service_name": "qotd", "transport_protocol": "TCP", "description": "Sends quote of the day to connected host"},
    18: {"service_name": "msp", "transport_protocol": "TCP", "description": "Message Send Protocol"},
    19: {"service_name": "chargen", "transport_protocol": "TCP", "description": "Character Generation service; sends endless stream of characters"},
    20: {"service_name": "ftp-data", "transport_protocol": "TCP, SCTP", "description": "FTP data port"},
    21: {"service_name": "ftp", "transport_protocol": "TCP", "description": "File Transfer Protocol (FTP) port; sometimes used by File Service Protocol (FSP)"},
    22: {"service_name": "ssh", "transport_protocol": "TCP", "description": "Secure Shell (SSH) service"},
    23: {"service_name": "telnet", "transport_protocol": "TCP", "description": "The Telnet service"},
    25: {"service_name": "smtp", "transport_protocol": "TCP", "description": "Simple Mail Transfer Protocol (SMTP)"},
    37: {"service_name": "time", "transport_protocol": "TCP", "description": "Time Protocol"},
    39: {"service_name": "rlp", "transport_protocol": "TCP", "description": "Resource Location Protocol"},
    42: {"service_name": "nameserver", "transport_protocol": "TCP", "description": "Internet Name Service"},
    43: {"service_name": "nicname", "transport_protocol": "TCP", "description": "WHOIS directory service"},
    49: {"service_name": "tacacs", "transport_protocol": "TCP", "description": "Terminal Access Controller Access Control System for TCP/IP based authentication and access"},
    50: {"service_name": "re-mail-ck", "transport_protocol": "TCP", "description": "Remote Mail Checking Protocol"},
53: {"service_name": "DNS / domain", "transport_protocol": "TCP, UDP", "description": "domain name services (such as BIND)"},
63: {"service_name": "whois++", "transport_protocol": "TCP, UDP", "description": "WHOIS++, extended WHOIS services"},
67: {"service_name": "bootps", "transport_protocol": "TCP, UDP", "description": "Bootstrap Protocol (BOOTP) services; also used by Dynamic Host Configuration Protocol (DHCP) services"},
68: {"service_name": "bootpc", "transport_protocol": "TCP, UDP", "description": "Bootstrap (BOOTP) client; also used by Dynamic Host Control Protocol (DHCP) clients"},
69: {"service_name": "tftp", "transport_protocol": "TCP, UDP", "description": "Trivial File Transfer Protocol (TFTP)"},
70: {"service_name": "gopher", "transport_protocol": "TCP, UDP", "description": "Gopher Internet document search and retrieval"},
71: {"service_name": "netrjs-1", "transport_protocol": "TCP, UDP", "description": "Remote Job Service"},
72: {"service_name": "netrjs-2", "transport_protocol": "TCP, UDP", "description": "Remote Job Service"},
73: {"service_name": "netrjs-3", "transport_protocol": "TCP, UDP", "description": "Remote Job Service"},
73: {"service_name": "netrjs-4", "transport_protocol": "TCP, UDP", "description": "Remote Job Service"},
79: {"service_name": "finger", "transport_protocol": "TCP, UDP", "description": "Finger service for user contact information"},
80: {"service_name": "http", "transport_protocol": "TCP", "description": "HyperText Transfer Protocol (HTTP) for World Wide Web (WWW) services"},
88: {"service_name": "kerberos", "transport_protocol": "TCP, UDP", "description": "Kerberos network authentication system"},
95: {"service_name": "supdup", "transport_protocol": "TCP", "description": "Telnet protocol extension"},
101: {"service_name": "hostname", "transport_protocol": "TCP, UDP", "description": "Hostname services on SRI-NIC machines"},
102: {"service_name": "iso-tsap", "transport_protocol": "TCP", "description": "ISO Development Environment (ISODE) network applications"},
105: {"service_name": "csnet-ns", "transport_protocol": "TCP, UDP", "description": "Mailbox nameserver; also used by CSO nameserver"},
107: {"service_name": "rtelnet", "transport_protocol": "TCP", "description": "Remote Telnet"},
109: {"service_name": "pop2", "transport_protocol": "TCP", "description": "Post Office Protocol version 2"}, 
110: {"service_name": "pop3", "transport_protocol": "TCP", "description": "Post Office Protocol version 3"},
111: {"service_name": "sunrpc", "transport_protocol": "TCP, UDP", "description": "Remote Procedure Call (RPC) Protocol for remote command execution used by Network Filesystem (NFS)"},
113: {"service_name": "auth", "transport_protocol": "TCP", "description": "Authentication and Ident protocols"},
115: {"service_name": "sftp", "transport_protocol": "TCP", "description": "Secure File Transfer Protocol (SFTP) services"},
117: {"service_name": "uucp-path", "transport_protocol": "TCP", "description": "Unix-to-Unix Copy Protocol (UUCP) Path services"},
119: {"service_name": "nntp", "transport_protocol": "TCP", "description": "Network News Transfer Protocol (NNTP) for the USENET discussion system"},
123: {"service_name": "ntp", "transport_protocol": "UDP", "description": "Network Time Protocol (NTP)"},
137: {"service_name": "netbios-ns", "transport_protocol": "UDP", "description": "NETBIOS Name Service used in Red Hat Enterprise Linux by Samba"},
138: {"service_name": "netbios-dgm", "transport_protocol": "UDP", "description": "NETBIOS Datagram Service used in Red Hat Enterprise Linux by Samba"},
139: {"service_name": "netbios-ssn", "transport_protocol": "TCP", "description": "NETBIOS Session Service used in Red Hat Enterprise Linux by Samba"},
143: {"service_name": "imap", "transport_protocol": "TCP", "description": "Internet Message Access Protocol (IMAP)"},
161: {"service_name": "snmp", "transport_protocol": "UDP", "description": "Simple Network Management Protocol (SNMP)"},
162: {"service_name": "snmptrap", "transport_protocol": "UDP", "description": "Traps for SNMP"},
163: {"service_name": "cmip-man", "transport_protocol": "TCP", "description": "Common Management Information Protocol (CMIP)"},
164: {"service_name": "cmip-agent", "transport_protocol": "TCP", "description": "Common Management Information Protocol (CMIP)"},
174: {"service_name": "mailq", "transport_protocol": "TCP", "description": "MAILQ email transport queue"},
177: {"service_name": "xdmcp", "transport_protocol": "UDP", "description": "X Display Manager Control Protocol (XDMCP)"},
178: {"service_name": "nextstep", "transport_protocol": "TCP", "description": "NeXTStep window server"},   
179: {'port': 179, 'service_name': 'bgp ', 'transport_protocol': 'TCP', 'description': 'Border Gateway Protocol\n'}, 191: {'port': 191, 'service_name': 'prospero ', 'transport_protocol': 'TCP', 'description': 'Prospero distributed filesystem services\n'}, 194: {'port': 194, 'service_name': 'irc ', 'transport_protocol': 'TCP', 'description': 'Internet Relay Chat (IRC)\n'}, 199: {'port': 199, 'service_name': 'smux ', 'transport_protocol': 'TCP', 'description': 'SNMP UNIX Multiplexer\n'}, 201: {'port': 201, 'service_name': 'at-rtmp ', 'transport_protocol': 'TCP', 'description': 'AppleTalk routing\n'}, 202: {'port': 202, 'service_name': 'at-nbp ', 'transport_protocol': 'TCP', 'description': 'AppleTalk name binding\n'}, 204: {'port': 204, 'service_name': 'at-echo ', 'transport_protocol': 'TCP', 'description': 'AppleTalk echo\n'}, 206: {'port': 206, 'service_name': 'at-zis ', 'transport_protocol': 'TCP', 'description': 'AppleTalk zone information\n'}, 209: {'port': 209, 'service_name': 'qmtp ', 'transport_protocol': 'TCP', 'description': 'Quick Mail Transfer Protocol (QMTP)\n'}, 210: {'port': 210, 'service_name': 'z39.50 ', 'transport_protocol': 'TCP', 'description': 'NISO Z39.50 database\n'}, 213: {'port': 213, 'service_name': 'ipx ', 'transport_protocol': 'TCP', 'description': 'Internetwork Packet Exchange (IPX), a datagram protocol commonly used in Novell Netware environments\n'}, 220: {'port': 220, 'service_name': 'imap3 ', 'transport_protocol': 'TCP', 'description': 'Internet Message Access Protocol version 3\n'}, 245: {'port': 245, 'service_name': 'link ', 'transport_protocol': 'TCP', 'description': 'LINK / 3-DNS iQuery service\n'}, 347: {'port': 347, 'service_name': 'fatserv ', 'transport_protocol': 'TCP', 'description': 'FATMEN file and tape management server\n'}, 363: {'port': 363, 'service_name': 'rsvp_tunnel ', 'transport_protocol': 'TCP', 'description': 'RSVP Tunnel\n'}, 369: {'port': 369, 'service_name': 'rpc2portmap ', 'transport_protocol': 'TCP', 'description': 'Coda file system portmapper\n'}, 370: {'port': 370, 'service_name': 'codaauth2 ', 'transport_protocol': 'TCP', 'description': 'Coda file system authentication services\n'}, 372: {'port': 372, 'service_name': 'ulistproc ', 'transport_protocol': 'TCP', 'description': 'UNIX LISTSERV\n'}, 389: {'port': 389, 'service_name': 'ldap ', 'transport_protocol': 'TCP', 'description': 'Lightweight Directory Access Protocol (LDAP)\n'}, 427: {'port': 427, 'service_name': 'svrloc ', 'transport_protocol': 'TCP', 'description': 'Service Location Protocol (SLP)\n'}, 434: {'port': 434, 'service_name': 'mobileip-agent ', 'transport_protocol': 'TCP', 'description': 'Mobile Internet Protocol (IP) agent\n'}, 435: {'port': 435, 'service_name': 'mobilip-mn ', 'transport_protocol': 'TCP', 'description': 'Mobile Internet Protocol (IP) manager\n'}, 443: {'port': 443, 'service_name': 'https ', 'transport_protocol': 'TCP', 'description': 'Secure Hypertext Transfer Protocol (HTTP)\n'}, 444: {'port': 444, 'service_name': 'snpp ', 'transport_protocol': 'TCP', 'description': 'Simple Network Paging Protocol\n'}, 445: {'port': 445, 'service_name': 'microsoft-ds ', 'transport_protocol': 'TCP', 'description': 'Server Message Block (SMB) over TCP/IP\n'}, 464: {'port': 464, 'service_name': 'kpasswd ', 'transport_protocol': 'TCP', 'description': 'Kerberos password and key changing services\n'}, 468: {'port': 468, 'service_name': 'photuris ', 'transport_protocol': 'TCP', 'description': 'Photuris session key management protocol\n'}, 487: {'port': 487, 'service_name': 'saft ', 'transport_protocol': 'TCP', 'description': 'Simple Asynchronous File Transfer (SAFT) protocol\n'}, 488: {'port': 488, 'service_name': 'gss-http ', 'transport_protocol': 'TCP', 'description': 'Generic Security Services (GSS) for HTTP\n'}, 496: {'port': 496, 'service_name': 'pim-rp-disc ', 'transport_protocol': 'TCP', 'description': 'Rendezvous Point Discovery (RP-DISC) for Protocol Independent Multicast (PIM) services\n'}, 500: {'port': 500, 'service_name': 'isakmp ', 'transport_protocol': 'TCP', 'description': 'Internet Security Association and Key Management Protocol (ISAKMP)\n'}, 535: {'port': 535, 'service_name': 'iiop ', 'transport_protocol': 'TCP', 'description': 'Internet Inter-Orb Protocol (IIOP)\n'}, 538: {'port': 538, 'service_name': 'gdomap ', 'transport_protocol': 'TCP', 'description': 'GNUstep Distributed Objects Mapper (GDOMAP)\n'}, 546: {'port': 546, 'service_name': 'dhcpv6-client ', 'transport_protocol': 'TCP', 'description': 'Dynamic Host Configuration Protocol (DHCP) version 6 client\n'}, 547: {'port': 547, 'service_name': 'dhcpv6-server ', 'transport_protocol': 'TCP', 'description': 'Dynamic Host Configuration Protocol (DHCP) version 6 Service\n'}, 554: {'port': 554, 'service_name': 'rtsp ', 'transport_protocol': 'TCP', 'description': 'Real Time Stream Control Protocol (RTSP)\n'}, 563: {'port': 563, 'service_name': 'nntps ', 'transport_protocol': 'TCP', 'description': 'Network News Transport Protocol over Secure Sockets Layer (NNTPS)\n'}, 565: {'port': 565, 'service_name': 'whoami ', 'transport_protocol': 'TCP', 'description': 'whoami user ID listing\n'}, 587: {'port': 587, 'service_name': 'submission ', 'transport_protocol': 'TCP', 'description': 'Mail Message Submission Agent (MSA)\n'}, 610: {'port': 610, 'service_name': 'npmp-local ', 'transport_protocol': 'TCP', 'description': 'Network Peripheral Management Protocol (NPMP) local / Distributed Queueing System (DQS)\n'}, 611: {'port': 611, 'service_name': 'npmp-gui ', 'transport_protocol': 'TCP', 'description': 'Network Peripheral Management Protocol (NPMP) GUI / Distributed Queueing System (DQS)\n'}, 612: {'port': 612, 'service_name': 'hmmp-ind ', 'transport_protocol': 'TCP', 'description': 'HyperMedia Management Protocol (HMMP) Indication / DQS\n'}, 631: {'port': 631, 'service_name': 'ipp ', 'transport_protocol': 'TCP', 'description': 'Internet Printing Protocol (IPP)\n'}, 636: {'port': 636, 'service_name': 'ldaps ', 'transport_protocol': 'TCP', 'description': 'Lightweight Directory Access Protocol over Secure Sockets Layer (LDAPS)\n'}, 674: {'port': 674, 'service_name': 'acap ', 'transport_protocol': 'TCP', 'description': 'Application Configuration Access Protocol (ACAP)\n'}, 694: {'port': 694, 'service_name': 'ha-cluster ', 'transport_protocol': 'TCP', 'description': 'Heartbeat services for High-Availability Clusters\n'}, 749: {'port': 749, 'service_name': 'kerberos-adm ', 'transport_protocol': 'TCP', 'description': "Kerberos version 5 (v5) 'kadmin' database administration\n"}, 750: {'port': 750, 'service_name': 'kerberos-iv ', 'transport_protocol': 'TCP', 'description': 'Kerberos version 4 (v4) services\n'}, 765: {'port': 765, 'service_name': 'webster ', 'transport_protocol': 'TCP', 'description': 'Network Dictionary\n'}, 767: {'port': 767, 'service_name': 'phonebook ', 'transport_protocol': 'TCP', 'description': 'Network Phonebook\n'}, 873: {'port': 873, 'service_name': 'rsync ', 'transport_protocol': 'TCP', 'description': 'rsync file transfer services\n'}, 992: {'port': 992, 'service_name': 'telnets ', 'transport_protocol': 'TCP', 'description': 'Telnet over Secure Sockets Layer (TelnetS)\n'}, 993: {'port': 993, 'service_name': 'imaps ', 'transport_protocol': 'TCP', 'description': 'Internet Message Access Protocol over Secure Sockets Layer (IMAPS)\n'}, 994: {'port': 994, 'service_name': 'ircs ', 'transport_protocol': 'TCP', 'description': 'Internet Relay Chat over Secure Sockets Layer (IRCS)\n'}, 995: {'port': 995, 'service_name': 'pop3s ', 'transport_protocol': 'TCP', 'description': 'Post Office Protocol version 3 over Secure Sockets Layer (POP3S) \n'}
}

def lookup_port(query):
  # Check if the query is a port number
  if query.isdigit():
    query = int(query)
    # Check if the port number is in the dictionary
    if query in port_data:
      data = port_data[query]
      data["port_number"] = query
      return data
    else:
      return "Invalid port number"
  # If the query is not a port number, assume it's a service name
  else:
     # Iterate through the dictionary and look for a match
     for port, data in port_data.items():
       if re.search(query, data["service_name"], re.IGNORECASE) or re.search(query, data["description"], re.IGNORECASE):
          data["port_number"] = port
          return data
     # If no match is found, return an error message
     return "No match found"

# Read the user's input
query = input("Enter a port number or service name: ")

# Look up the port and print the result
result = lookup_port(query)
print(result)
