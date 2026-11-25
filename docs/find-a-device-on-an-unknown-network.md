# Finding a device on an unknown network

You may be cabled into a sensor's internal network with no address plan. This is how to
find which device answers on the sensor's UDP port. Agree it with the equipment owner first.

1. **Listen first and send nothing.** Watch ARP on the interface for a minute. This shows
   the subnet and which addresses are in use:
   `sudo tcpdump -nn -i eth0 arp`. `ip neigh show dev eth0` also works after a while.
2. **Take an unused address.** Choose one that never appeared in step 1. Confirm that
   nothing answers for it: `sudo arping -D -I eth0 -c 3 <address>`. Then add it:
   `scapegoat net addr_add --iface eth0 --cidr <address>/<prefix> --confirm`.
3. **Probe the port on each device seen in step 1.** In one terminal, watch ICMP:
   `sudo tcpdump -nn -i eth0 icmp`. In another, send one empty UDP datagram to each address:
   `for ip in <addresses>; do nc -u -z -w 1 "$ip" <port>; done`.
   - A device that answers **ICMP "udp port <port> unreachable"** has the port closed.
   - A device that answers **nothing** while it still answers ARP has the port open. That
     is the one.
4. Set that address as the session's `peer` and check `scapegoat status`.

Each probe puts one small datagram on the sensor's network. Do it once, after agreeing it
with the equipment owner. scapegoat's own tools never send probes (`scapegoat net` is read-only).
