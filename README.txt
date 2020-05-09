Ping implementation by Adam Wolnikowski
for 2020 Cloudflare remote internship application - systems

Credit to Beej's Guide to Network Programming
(https://beej.us/guide/bgnet/html/) for network programming
information used in the process of writing this program.

Output format is based on the Ubuntu ping utility.

To compile:
 $ make

To run:
 $ sudo ./ping <host>

The program supports hostnames, IPV4 addresses, and IPV6 addresses
to be supplied for the <host> argument.

The program also supports a ttl option, invoked like so:
$ sudo ./ping www.google.com -t 54

Note on IPV6 functionality:
All of the networks I have access to (home network, VPN into
school network, mobile hotspot) do not support IPV6, so I was unable
to thoroughly test the IPV6 components of the program.

Copyright © 2020 Adam Wolnikowski
adam.wolnikowski@yale.edu - awolnik.github.io

