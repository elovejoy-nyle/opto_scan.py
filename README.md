<pre>
# no optos respond:
$ ./opto_scan.py 192.168.1.69 --wait 60
[+] Network:   192.168.1.0/24
[+] Broadcast: 192.168.1.255
[+] Waiting up to 60 seconds

[+] Sending discovery packet (1/3)
[+] Sending discovery packet (2/3)
[+] Sending discovery packet (3/3)

[-] No matching targets found.

# An opto response:  
$ ./opto_scan.py 192.168.1.69 --wait 60
[+] Network:   192.168.1.0/24
[+] Broadcast: 192.168.1.255
[+] Waiting up to 60 seconds

[+] Sending discovery packet (1/3)
[FOUND] 192.168.1.114    00:a0:3d:12:34:56    opto-12-34-56

[+] Found 1 target(s). 

# use --all flag to list even non opto devices: #ok thats a bug lol
$ ./opto_scan.py 192.168.1.69 --all  
[FOUND] 192.168.1.1      3c:52:82:aa:bb:cc    opto-aa-bb-cc
[FOUND] 192.168.1.10     dc:a6:32:11:22:33    opto-11-22-33
[FOUND] 192.168.1.114    00:a0:3d:12:34:56    opto-12-34-56

</pre>
