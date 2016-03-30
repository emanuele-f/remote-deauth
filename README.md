# remote-deauth

dependencies
------------
- libpcap
- libncurses
- glib

Thanks to Jouni Malinen [wpa_supplicant](https://github.com/realdesktop/wpa_supplicant) project for IEEE 802.11 headers and routines.

server
------
Monitor IEEE 801.11 ap and clients using libpcap facilities.
Receives commands from the client for blacklisting specific clients or AP and sends monitor data.
The blacklisted stations will be flooded by deauth packets.
No broadcast deauth allowed.

- make server
- sudo ./server

You will need an external tool to start the interface in monitor mode.
Current setup assumes mon0 device name.

client
------
Should presend in a ncurses interface the monitor data from the server.
Spacebar should toggle host selection for blacklisting.

- make client
- ./client
