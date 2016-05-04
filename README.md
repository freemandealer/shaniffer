Shaniffer is the shabby sniffer tool to monitor network packets.

---

Compile & Install:

    make install # root privilege is required

Capture packets:
    
    shapture

Provide interface name if you want to capture packets through specific interface. e.g:
    
    shapture wlan0

Stop Capturing:
    
    press Ctrl + C

Inforation of captured packets are stored in /var/shanilog.txt. The log is human-readable, but
considering the quantity, we provide a filter to help locating information you are interested in.
e.g:

    shailter srcip 192.168.1.1 # filtering packets whose source ip is 192.168.1.1
    shailter dstmac FF-FF-FF-FF-FF-FF # filtering packets whose destination hardware address is
    FF-FF-FF-FF-FF-FF
    shailter raw "secret" # filtering packets containing the string "secret"

Bug report to <freeman.zhang1992@gmail.com>
