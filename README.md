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

You will need an external tool to start the interface in monitor mode and to
change channel.

If you have installed the aircrack suite, you can use:

`sudo airmon-ng start [iface]`

`sudo airodump-ng [mon_iface] -c [channel]`

Current setup assumes mon0 as the monitor interface device.

client
------
Connects to the server and presents the monitor data in an ncurses interface.

- make client
- ./client

Change selction with arrow keys.
Press enter on an AP to expand/collapse its hosts list.
Press spacebar to add/remove host from blacklist.

You can create a mac -> name mapping file `hosts.cfg` with the format:

`xx:xx:xx:xx:xx:xx | alias`

which will be used to tag mac addresses owners in the program.


