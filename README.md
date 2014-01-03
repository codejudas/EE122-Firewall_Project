EE122-Firewall_Project
======================

Original project spec: http://www-inst.eecs.berkeley.edu/~ee122/fa13/projects/project3b/spec.pdf

Project from EE122 in which I implemented a firewall on an Ubuntu virtual machine. The instructors provided a simplified network interface running on Ubuntu. We implemented the firewall to fit the following specifications:

-Accepts rules from rules.conf
-rules could be of form <pass/drop> <protocol> <ipaddress> <portnumber>
-protocols supported were ICMP, TCP, UDP, DNS.
-Ip addresses could be unique or specify a range via prefix.
-Ip address field could also be a countr code (ie 'fr'), the firewall would then search the geoipdb.txt file for a match.

Special Cases
=============

deny tcp * *
This not only drops the tcp packet but also responds to the source with an RST packet to stop further attempts.

deny dns <domain name>
This essentially redirected matching domain names to a specific ip address. It crafts a DNS response to the original query with this redirect ip address.

log http <host name>
Logged an http connection pair and wrote to http.log. Each request/response pair for a matching host would be recorded in the form:

host_name method path version status_code object_size
